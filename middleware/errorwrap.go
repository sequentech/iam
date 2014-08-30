package middleware

import (
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"runtime/debug"
)

// RavenClientIface is used so that we do not really depend on an specific
// implementation of the RavenClient in this file
type RavenClientIface interface {
	CaptureMessage(...string) (string, error)
}

// Ravenable is used to get the RavenClient from an object
type Ravenable interface {
	RavenClient() RavenClientIface
}

// HandledError is the type of managed error that can happen in app views
type HandledError struct {
	Err     error
	Code    int
	Message string
	CodedMessage string
}



type handledErrorJson struct {
	Message string `json:"error"`
	CodedMessage string `json:"error_code"`
}

// ErrorHandler is the signature of an app view that handles errors
type ErrorHandler func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) *HandledError

// ErrorWrap is a struct used to create an instance of this middleware.
type ErrorWrap struct {
	Raven RavenClientIface
}

// NewErrorWrap instantiates the ErrorWrap middleware
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

			content, err2 := json.Marshal(&handledErrorJson{err.Message, err.CodedMessage})
			if err2 != nil {
				panic(err2)
			}
			http.Error(w, string(content), err.Code)
		}
	}
}
