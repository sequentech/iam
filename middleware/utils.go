package middleware

import (
	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

// RavenClientIface is used so that we do not really depend on an specific
// implementation of the RavenClient in this file
type RavenClientIface interface {
	CaptureMessage(...string) (string, error)
}

type HandlerFunc func(rw http.ResponseWriter, r *http.Request, p httprouter.Params, next httprouter.Handle)

type Handler interface {
	ServeHTTP(rw http.ResponseWriter, r *http.Request, p httprouter.Params, next httprouter.Handle)
}

func (h HandlerFunc) ServeHTTP(rw http.ResponseWriter, r *http.Request, p httprouter.Params, next httprouter.Handle) {
	h(rw, r, p, next)
}

type middlew struct {
	handler Handler
	next    *middlew
}

func (m middlew) ServeHTTP(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	m.handler.ServeHTTP(rw, r, p, m.next.ServeHTTP)
}

func build(handlers []Handler, lastHandle httprouter.Handle) middlew {
	var next middlew

	if len(handlers) == 0 {
		return lastMiddleware(lastHandle)
	} else if len(handlers) > 1 {
		next = build(handlers[1:], lastHandle)
	} else {
		next = lastMiddleware(lastHandle)
	}

	return middlew{handlers[0], &next}
}

func lastMiddleware(handle httprouter.Handle) middlew {
	return middlew{
		HandlerFunc(func(rw http.ResponseWriter, r *http.Request, p httprouter.Params, _ httprouter.Handle) {
			handle(rw, r, p)
		}),
		&middlew{},
	}
}

// Join allows you to add middleware to a handle, returning a handle
func Join(handle httprouter.Handle, handlers ...Handler) httprouter.Handle {
	return func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
		mware := build(handlers, handle)
		mware.ServeHTTP(rw, r, p)
	}
}

type Wrapper struct {
	handler negroni.Handler
}

func (w Wrapper) ServeHTTP(rw http.ResponseWriter, r *http.Request, p httprouter.Params, next httprouter.Handle) {
	f := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	w.handler.ServeHTTP(rw, r, f)
	next(rw, r, p)
}

//  Wrap allows to convert a negroni middleware into our own type of middleware
func Wrap(handler negroni.Handler) Handler {
	return &Wrapper{handler: handler}
}
