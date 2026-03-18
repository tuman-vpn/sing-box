package ocm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type statusPayload struct {
	FiveHourUtilization float64 `json:"five_hour_utilization"`
	FiveHourReset       int64   `json:"five_hour_reset"`
	WeeklyUtilization   float64 `json:"weekly_utilization"`
	WeeklyReset         int64   `json:"weekly_reset"`
	PlanWeight          float64 `json:"plan_weight"`
}

type aggregatedStatus struct {
	fiveHourUtilization float64
	weeklyUtilization   float64
	totalWeight         float64
	fiveHourReset       time.Time
	weeklyReset         time.Time
}

func resetToEpoch(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s aggregatedStatus) equal(other aggregatedStatus) bool {
	return s.fiveHourUtilization == other.fiveHourUtilization &&
		s.weeklyUtilization == other.weeklyUtilization &&
		s.totalWeight == other.totalWeight &&
		resetToEpoch(s.fiveHourReset) == resetToEpoch(other.fiveHourReset) &&
		resetToEpoch(s.weeklyReset) == resetToEpoch(other.weeklyReset)
}

func (s aggregatedStatus) toPayload() statusPayload {
	return statusPayload{
		FiveHourUtilization: s.fiveHourUtilization,
		FiveHourReset:       resetToEpoch(s.fiveHourReset),
		WeeklyUtilization:   s.weeklyUtilization,
		WeeklyReset:         resetToEpoch(s.weeklyReset),
		PlanWeight:          s.totalWeight,
	}
}

func (s *Service) handleStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, r, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed")
		return
	}

	var provider credentialProvider
	var userConfig *option.OCMUser
	if len(s.options.Users) > 0 {
		if r.Header.Get("X-Api-Key") != "" || r.Header.Get("Api-Key") != "" {
			writeJSONError(w, r, http.StatusBadRequest, "invalid_request_error",
				"API key authentication is not supported; use Authorization: Bearer with an OCM user token")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "missing api key")
			return
		}
		clientToken := strings.TrimPrefix(authHeader, "Bearer ")
		if clientToken == authHeader {
			writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "invalid api key format")
			return
		}
		username, ok := s.userManager.Authenticate(clientToken)
		if !ok {
			writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "invalid api key")
			return
		}

		userConfig = s.userConfigMap[username]
		var err error
		provider, err = credentialForUser(s.userConfigMap, s.providers, username)
		if err != nil {
			writeJSONError(w, r, http.StatusInternalServerError, "api_error", err.Error())
			return
		}
	} else {
		provider = s.providers[s.options.Credentials[0].Tag]
	}
	if provider == nil {
		writeJSONError(w, r, http.StatusInternalServerError, "api_error", "no credential available")
		return
	}

	textFormat := r.URL.Query().Get("format") == "text"

	if r.URL.Query().Get("watch") == "true" {
		s.handleStatusStream(w, r, provider, userConfig, textFormat)
		return
	}

	provider.pollIfStale()
	status := s.computeAggregatedUtilization(provider, userConfig)

	if textFormat {
		credentials := s.visibleCredentials(provider, userConfig)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(formatStatusText(status, credentials, "OCM"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status.toPayload())
}

func (s *Service) handleStatusStream(w http.ResponseWriter, r *http.Request, provider credentialProvider, userConfig *option.OCMUser, textFormat bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, r, http.StatusInternalServerError, "api_error", "streaming not supported")
		return
	}

	subscription, done, err := s.statusObserver.Subscribe()
	if err != nil {
		writeJSONError(w, r, http.StatusInternalServerError, "api_error", "service closing")
		return
	}
	defer s.statusObserver.UnSubscribe(subscription)

	provider.pollIfStale()

	if textFormat {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)

	last := s.computeAggregatedUtilization(provider, userConfig)
	buf := &bytes.Buffer{}
	if textFormat {
		fmt.Fprintf(buf, "────── %s ──────\n\n", time.Now().Format("15:04:05"))
		buf.Write(formatStatusText(last, s.visibleCredentials(provider, userConfig), "OCM"))
	} else {
		json.NewEncoder(buf).Encode(last.toPayload())
	}
	_, writeErr := w.Write(buf.Bytes())
	if writeErr != nil {
		return
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-subscription:
			for {
				select {
				case <-subscription:
				default:
					goto drained
				}
			}
		drained:
			current := s.computeAggregatedUtilization(provider, userConfig)
			if current.equal(last) {
				continue
			}
			last = current
			buf.Reset()
			if textFormat {
				fmt.Fprintf(buf, "\n────── %s ──────\n\n", time.Now().Format("15:04:05"))
				buf.Write(formatStatusText(current, s.visibleCredentials(provider, userConfig), "OCM"))
			} else {
				json.NewEncoder(buf).Encode(current.toPayload())
			}
			_, writeErr = w.Write(buf.Bytes())
			if writeErr != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Service) computeAggregatedUtilization(provider credentialProvider, userConfig *option.OCMUser) aggregatedStatus {
	var totalWeightedRemaining5h, totalWeightedRemainingWeekly, totalWeight float64
	now := time.Now()
	var totalWeightedHoursUntil5hReset, total5hResetWeight float64
	var totalWeightedHoursUntilWeeklyReset, totalWeeklyResetWeight float64
	for _, credential := range provider.allCredentials() {
		if !credential.isAvailable() {
			continue
		}
		if userConfig != nil && userConfig.ExternalCredential != "" && credential.tagName() == userConfig.ExternalCredential {
			continue
		}
		if userConfig != nil && !userConfig.AllowExternalUsage && credential.isExternal() {
			continue
		}
		weight := credential.planWeight()
		remaining5h := credential.fiveHourCap() - credential.fiveHourUtilization()
		if remaining5h < 0 {
			remaining5h = 0
		}
		remainingWeekly := credential.weeklyCap() - credential.weeklyUtilization()
		if remainingWeekly < 0 {
			remainingWeekly = 0
		}
		totalWeightedRemaining5h += remaining5h * weight
		totalWeightedRemainingWeekly += remainingWeekly * weight
		totalWeight += weight

		fiveHourReset := credential.fiveHourResetTime()
		if !fiveHourReset.IsZero() {
			hours := fiveHourReset.Sub(now).Hours()
			if hours > 0 {
				totalWeightedHoursUntil5hReset += hours * weight
				total5hResetWeight += weight
			}
		}
		weeklyReset := credential.weeklyResetTime()
		if !weeklyReset.IsZero() {
			hours := weeklyReset.Sub(now).Hours()
			if hours > 0 {
				totalWeightedHoursUntilWeeklyReset += hours * weight
				totalWeeklyResetWeight += weight
			}
		}
	}
	if totalWeight == 0 {
		return aggregatedStatus{
			fiveHourUtilization: 100,
			weeklyUtilization:   100,
		}
	}
	result := aggregatedStatus{
		fiveHourUtilization: 100 - totalWeightedRemaining5h/totalWeight,
		weeklyUtilization:   100 - totalWeightedRemainingWeekly/totalWeight,
		totalWeight:         totalWeight,
	}
	if total5hResetWeight > 0 {
		avgHours := totalWeightedHoursUntil5hReset / total5hResetWeight
		result.fiveHourReset = now.Add(time.Duration(avgHours * float64(time.Hour)))
	}
	if totalWeeklyResetWeight > 0 {
		avgHours := totalWeightedHoursUntilWeeklyReset / totalWeeklyResetWeight
		result.weeklyReset = now.Add(time.Duration(avgHours * float64(time.Hour)))
	}
	return result
}

func (s *Service) rewriteResponseHeaders(headers http.Header, provider credentialProvider, userConfig *option.OCMUser) {
	status := s.computeAggregatedUtilization(provider, userConfig)
	headers.Set("x-codex-primary-used-percent", strconv.FormatFloat(status.fiveHourUtilization, 'f', 2, 64))
	headers.Set("x-codex-secondary-used-percent", strconv.FormatFloat(status.weeklyUtilization, 'f', 2, 64))
	if !status.fiveHourReset.IsZero() {
		headers.Set("x-codex-primary-reset-at", strconv.FormatInt(status.fiveHourReset.Unix(), 10))
	} else {
		headers.Del("x-codex-primary-reset-at")
	}
	if !status.weeklyReset.IsZero() {
		headers.Set("x-codex-secondary-reset-at", strconv.FormatInt(status.weeklyReset.Unix(), 10))
	} else {
		headers.Del("x-codex-secondary-reset-at")
	}
	if status.totalWeight > 0 {
		headers.Set("X-OCM-Plan-Weight", strconv.FormatFloat(status.totalWeight, 'f', -1, 64))
	}
	rateLimitSuffixes := [...]string{
		"-primary-used-percent",
		"-primary-reset-at",
		"-secondary-used-percent",
		"-secondary-reset-at",
		"-secondary-window-minutes",
		"-limit-name",
	}
	for key := range headers {
		lowerKey := strings.ToLower(key)
		if !strings.HasPrefix(lowerKey, "x-") {
			continue
		}
		for _, suffix := range rateLimitSuffixes {
			if strings.HasSuffix(lowerKey, suffix) {
				if strings.TrimSuffix(lowerKey, suffix) != "x-codex" {
					headers.Del(key)
				}
				break
			}
		}
	}
}

type tierGroup struct {
	label       string
	weight      float64
	available   int
	unavailable int
}

func (s *Service) visibleCredentials(provider credentialProvider, userConfig *option.OCMUser) []Credential {
	var result []Credential
	for _, credential := range provider.allCredentials() {
		if userConfig != nil && userConfig.ExternalCredential != "" && credential.tagName() == userConfig.ExternalCredential {
			continue
		}
		if userConfig != nil && !userConfig.AllowExternalUsage && credential.isExternal() {
			continue
		}
		result = append(result, credential)
	}
	return result
}

func groupCredentials(credentials []Credential) []tierGroup {
	type key struct {
		label  string
		weight float64
	}
	counts := make(map[key]*tierGroup)
	var order []key
	for _, credential := range credentials {
		label := credential.tierLabel()
		weight := credential.planWeight()
		k := key{label, weight}
		group, exists := counts[k]
		if !exists {
			group = &tierGroup{label: label, weight: weight}
			counts[k] = group
			order = append(order, k)
		}
		if credential.isAvailable() {
			group.available++
		} else {
			group.unavailable++
		}
	}
	groups := make([]tierGroup, 0, len(order))
	for _, k := range order {
		groups = append(groups, *counts[k])
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].weight > groups[j].weight
	})
	return groups
}

func formatBar(ratio float64, width int) string {
	filled := int(math.Round(ratio * float64(width)))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func centerLabel(label string, width int) string {
	runeCount := utf8.RuneCountInString(label)
	if runeCount >= width {
		runes := []rune(label)
		return string(runes[:width])
	}
	pad := width - runeCount
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + label + strings.Repeat(" ", right)
}

func formatStatusText(status aggregatedStatus, credentials []Credential, serviceName string) []byte {
	groups := groupCredentials(credentials)
	buf := &bytes.Buffer{}

	var summaryParts []string
	for _, group := range groups {
		total := group.available + group.unavailable
		if total > 1 {
			summaryParts = append(summaryParts, fmt.Sprintf("%d× %s", total, group.label))
		} else {
			summaryParts = append(summaryParts, group.label)
		}
	}
	weightStr := strconv.FormatFloat(status.totalWeight, 'f', -1, 64)
	fmt.Fprintf(buf, "%s (%s, wt %s):\n\n", serviceName, strings.Join(summaryParts, ", "), weightStr)

	barWidth := 20
	fiveHourBar := formatBar(status.fiveHourUtilization/100, barWidth)
	fmt.Fprintf(buf, "5h  %s  %5.2f%%", fiveHourBar, status.fiveHourUtilization)
	if !status.fiveHourReset.IsZero() {
		remaining := time.Until(status.fiveHourReset)
		if remaining > 0 {
			fmt.Fprintf(buf, "  resets in %s", log.FormatDuration(remaining))
		}
	}
	buf.WriteByte('\n')

	weeklyBar := formatBar(status.weeklyUtilization/100, barWidth)
	fmt.Fprintf(buf, "7d  %s  %5.2f%%", weeklyBar, status.weeklyUtilization)
	if !status.weeklyReset.IsZero() {
		remaining := time.Until(status.weeklyReset)
		if remaining > 0 {
			fmt.Fprintf(buf, "  resets in %s", log.FormatDuration(remaining))
		}
	}
	buf.WriteByte('\n')

	var cards []string
	for _, group := range groups {
		if group.available > 0 {
			label := group.label
			if group.available > 1 {
				label += " * " + strconv.Itoa(group.available)
			}
			cards = append(cards, centerLabel(label, 12))
		}
		if group.unavailable > 0 {
			label := group.label + " ×"
			if group.unavailable > 1 {
				label += strconv.Itoa(group.unavailable)
			}
			cards = append(cards, centerLabel(label, 12))
		}
	}

	if len(cards) > 0 {
		buf.WriteByte('\n')
		writeCardRows(buf, cards)
	}

	return buf.Bytes()
}

func writeCardRows(buf *bytes.Buffer, cards []string) {
	const cardsPerRow = 5
	for i := 0; i < len(cards); i += cardsPerRow {
		end := i + cardsPerRow
		if end > len(cards) {
			end = len(cards)
		}
		row := cards[i:end]

		for j := range row {
			if j > 0 {
				buf.WriteByte(' ')
			}
			buf.WriteString("┌────────────┐")
		}
		buf.WriteByte('\n')

		for j, card := range row {
			if j > 0 {
				buf.WriteByte(' ')
			}
			buf.WriteString("│")
			buf.WriteString(card)
			buf.WriteString("│")
		}
		buf.WriteByte('\n')

		for j := range row {
			if j > 0 {
				buf.WriteByte(' ')
			}
			buf.WriteString("└────────────┘")
		}
		buf.WriteByte('\n')
	}
}
