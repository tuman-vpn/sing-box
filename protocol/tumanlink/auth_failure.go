package tumanlink

import "sync/atomic"

// AuthFailureHandler receives TL1 causes that the link cannot recover from on
// its own: client.ErrCredentialEpochRequired (the host must fetch a newer
// credential epoch) and descriptor Refresh causes, including
// ErrDescriptorRefreshRequired (the host must fetch a newer signed
// descriptor). tag is the endpoint tag. A normal Down or Close is never
// reported, and a repeated cause is reported once per device generation.
//
// The handler runs on the endpoint's event goroutine and must not block.
// Endpoint.Close waits for that goroutine, so a handler that closes or
// restarts the box must do it asynchronously.
type AuthFailureHandler func(tag string, cause error)

var authFailureHandler atomic.Pointer[AuthFailureHandler]

// SetAuthFailureHandler installs the process-wide handler and returns the
// previous one. nil removes it. A notification already in flight may still
// reach the previous handler once. The fork only logs these causes; apps wire
// their own notification plumbing here (for example from an include file
// added by an app patch).
func SetAuthFailureHandler(handler AuthFailureHandler) AuthFailureHandler {
	var previous *AuthFailureHandler
	if handler == nil {
		previous = authFailureHandler.Swap(nil)
	} else {
		previous = authFailureHandler.Swap(&handler)
	}
	if previous == nil {
		return nil
	}
	return *previous
}

func notifyAuthFailure(tag string, cause error) {
	if handler := authFailureHandler.Load(); handler != nil {
		(*handler)(tag, cause)
	}
}
