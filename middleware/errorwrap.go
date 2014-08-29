package middleware

import (
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/kisielk/raven-go/raven"
	"net/http"
	"runtime/debug"
)

type Ravenable interface {
	RavenClient() *raven.Client
}

// HandledError is the type of managed error that can happen in app views
type HandledError struct {
	Err     error
	Code    int
	Message string
}

// ErrorHandler is the signature of an app view that handles errors
type ErrorHandler func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) *HandledError

// ErrorWrap is a struct used to create an instance of this middleware.
type ErrorWrap struct {
	Raven *raven.Client
}

func NewErrorWrap(r Ravenable) *ErrorWrap {
	return &ErrorWrap{Raven: r.RavenClient()}
}

// ErrorWrap handles errors nicely and returns an standard httprouter.Handle.
func (ew *ErrorWrap) Do(handle ErrorHandler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		if err := handle(w, r, p); err != nil {
			// record internal errors
			if err.Code == http.StatusInternalServerError && ew.Raven != nil {
				msg := fmt.Sprintf("500 Internal Server Error: message='%s', err=%v, stack=%v", err.Message, err.Err, debug.Stack())
				ew.Raven.CaptureMessage(msg)
			}

			content, err2 := json.Marshal(&errorJson{err.Message})
			if err2 != nil {
				panic(err2)
			}
			http.Error(w, string(content), err.Code)
		}
	}
}
