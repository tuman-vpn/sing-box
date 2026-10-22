# Tuman fork of sing-box-extended

This repository (`tuman-vpn/sing-box`, branch `tuman`) is
[sing-box-extended](https://github.com/shtorm-7/sing-box-extended) plus a short
patch series that adds the TL1 `tuman-link` endpoint. Everything else is
upstream. The Tuman iOS and desktop apps pin this repository as their
`SingBox/sing-box` submodule.

## What the fork adds

| Path | Purpose |
| --- | --- |
| `constant/tumanlink.go` | `TypeTumanLink = "tuman-link"` |
| `option/tumanlink.go` | `TumanLinkEndpointOptions` (descriptor union, credentials, setup order, cover pool and profile) |
| `protocol/tumanlink/` | Endpoint: credential loading, descriptor verification, link lifecycle and reconnect, `SetAuthFailureHandler` hook |
| `transport/tumanlink/` | gVisor netstack on top of `link/host/packetdev` |
| `include/tumanlink*.go` | Registration (`with_gvisor`) and a stub that asks for the tag |
| `docs/configuration/endpoint/tuman-link.md` | Option reference |
| `examples/tuman-link/` | `config.json` (local mixed proxy) and `tun.json` (whole device) |

Edits to upstream files are kept to these places:

* `include/registry.go`: one line, `registerTumanLinkEndpoint(registry)`.
* `constant/proxy.go`: the `ProxyDisplayName` case (`"Tuman Link"`).
* `go.mod` / `go.sum`: `github.com/tuman-vpn/link` and its dependencies.

The docs page is deliberately not added to `mkdocs.yml` or the endpoint index,
so docs never conflict on a rebase.

The protocol itself lives in [`github.com/tuman-vpn/link`](https://github.com/tuman-vpn/link)
(`link/docs/singbox.md` there is the host contract this endpoint implements).

The optional `cover_profile` selects `chrome` (default), `chrome-1pkt` or
`apple` for the QUIC cover handshake. It requires `quic` in `setup_order` and
is validated by `sing-box check`. Both examples use `apple` with the
h3-capable allowlisted cover name `www.google.com`.

## Building

`tuman-link` needs the `with_gvisor` build tag and a Unix-like host (its
credential permission checks do not work on Windows yet). The apps build with
`with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_conntrack`.

`github.com/tuman-vpn/link` is a **private** module for now. Builders need
GitHub access to `tuman-vpn/link` (ssh key or an https credential helper) and:

```bash
export GOPRIVATE=github.com/tuman-vpn
go build -tags with_gvisor ./cmd/sing-box
go test -tags with_gvisor ./protocol/tumanlink/... ./transport/tumanlink/... ./option/... ./include/...
./sing-box check -c examples/tuman-link/config.json
```

`GOPRIVATE` makes Go fetch the module directly over git instead of through
`proxy.golang.org`/`sum.golang.org`, which cannot see private repositories. If
your git is not authenticated for https, map just this organisation to ssh:
`git config --global url."git@github.com:tuman-vpn/".insteadOf "https://github.com/tuman-vpn/"`.
To build against a local link checkout, use a `go.work` or a temporary
`go mod edit -replace=github.com/tuman-vpn/link=../link`; never commit a replace.

## How the apps consume it

* `ios/SingBox/sing-box` and `desktop/SingBox/sing-box` are submodules of
  `https://github.com/tuman-vpn/sing-box.git`, checked out at a release tag
  (`v<extended tag>-tuman.N`).
* Their build scripts (`ios/SingBox/build-apple.sh`, `desktop/SingBox/build.sh`,
  `desktop/SingBox/build-darwin.sh`, `desktop/SingBox/build.ps1` and the
  router `Makefile`) export `GOPRIVATE=github.com/tuman-vpn`
  and still apply the apps' own patch series on top (DNS, logging and
  callback plumbing that is app-specific). `tuman-link` is no longer one of
  those patches.
* App notifications: the fork only logs credential-epoch and
  descriptor-refresh causes. The apps' `tuman-link-auth-callback.patch` adds
  `NotifyOutboundAuthFailureTL1` to their `common/tuman` package and installs
  it with `tumanlink.SetAuthFailureHandler` from an `include/` file. Any other
  embedder can do the same:

  ```go
  tumanlink.SetAuthFailureHandler(func(tag string, cause error) {
      // client.ErrCredentialEpochRequired: fetch a new credential epoch.
      // otherwise (descriptor Refresh): fetch a newer signed descriptor.
  })
  ```

## Syncing with sing-box-extended

Remotes:

```bash
git remote add extended https://github.com/shtorm-7/sing-box-extended.git
git remote add upstream https://github.com/SagerNet/sing-box.git   # reference only
git fetch extended --tags
git tag -l 'v*-extended-*' --sort=-creatordate | head
```

The series is a few commits on top of an extended release tag, so a sync is a
rebase of exactly those commits:

```bash
OLD=v1.13.18-extended-2.6.5      # base of the current series
NEW=v1.14.3-extended-2.7.3       # target extended tag
git switch tuman
LINK=$(go list -m -f '{{.Version}}' github.com/tuman-vpn/link)   # keep this link version
git branch tuman-$OLD            # optional: keep the old series as a branch
git rebase --onto "$NEW" "$OLD" tuman
```

Expected conflicts:

* `go.mod` / `go.sum` (every sync): take the new tag's files, re-add link and
  tidy:

  ```bash
  git checkout --ours go.mod go.sum    # during a rebase, "ours" is the new base
  go mod edit -require=github.com/tuman-vpn/link@$LINK
  GOPRIVATE=github.com/tuman-vpn go mod tidy
  git add go.mod go.sum
  ```

* `include/registry.go`: the single `registerTumanLinkEndpoint(registry)`
  line in `EndpointRegistry()`, next to `registerWireGuardEndpoint`. Keep it.
* `constant/proxy.go`: only if upstream edits the `ProxyDisplayName` cases
  around `TypeWireGuard`; re-add the two-line `TypeTumanLink` case.

Then `git rebase --continue`, run `go mod tidy` once more on the final tree,
and run the build, vet, tests and `sing-box check` commands above. A rebase
that applies cleanly can still fail to compile when upstream changes the
adapter interfaces; fix that in the endpoint commit (for example, the
`v1.14` releases changed `Start(stage)` to `Start(stage, *adapter.Scope)` and
`InterfaceUpdated()` to `InterfaceUpdated(context.Context)`).

Publish:

```bash
git push --force-with-lease origin tuman   # old releases stay reachable by tag
git tag -a "$NEW-tuman.1" -m "tuman-link on $NEW"
git push origin "$NEW-tuman.1"
```

Tag naming: `v<extended tag>-tuman.N`, with `N` starting at 1 for each new
extended base and increasing for fork-only changes on the same base
(`v1.13.18-extended-2.6.5-tuman.1`, `...-tuman.2`, ...). Then bump the app
submodules to the new tag and re-check their patch series with
`git apply --check`.

## Link dependency

`go.mod` requires a tagged `github.com/tuman-vpn/link` release (currently
`v0.3.0`). To pick up link changes, tag a new link release, then
`go get github.com/tuman-vpn/link@vX.Y.Z && go mod tidy` (with `GOPRIVATE`) and
release a new `-tuman.N` tag. While link is private, every builder (developer
machines and CI) needs `GOPRIVATE=github.com/tuman-vpn` and read access to the
repository; once link is public, `GOPRIVATE` can be dropped.
