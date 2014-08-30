package middleware

import (
	"strings"
	"github.com/julienschmidt/httprouter"
	"github.com/agoravoting/authapi/util"
	"github.com/codegangsta/negroni"
	"net/http"
	"net/http/httptest"
	"testing"
	"errors"
)

// wrapServer is a test type used for testing the ErrorWrap Raven handling
type wrapServer struct {
	Msgs string
}

// RavenClient implements middleware.Ravenable, needed for the ErrorWrap middleware
func (s *wrapServer) RavenClient() RavenClientIface {
	return s
}

// CaptureMessage registers in Msgs the last captured message
func (s *wrapServer) CaptureMessage(msgs ...string) (id string, err error) {
		s.Msgs = strings.Join(msgs, ";")
	return "1", nil
}

// TestErrorWrap creates a server with a method that raises an error
// and checks that ErrorWrap works as expected
func TestErrorWrapOK(t *testing.T) {
	recorder := httptest.NewRecorder()
	raven := &wrapServer{}
	wrap := NewErrorWrap(raven)
	router := httprouter.New()
	handler := negroni.New(negroni.Wrap(router))

	router.GET("/hello", wrap.Do(testHelloOK))

	req, _ := http.NewRequest("GET", "/hello", nil)
	handler.ServeHTTP(recorder, req)

	util.Expect(t, recorder.Code, http.StatusOK)
	util.Expect(t, recorder.Body.Len(), len("Hello World!"))
	util.Expect(t, len(raven.Msgs), 0)
}

func TestErrorWrapNotFound(t *testing.T) {
	recorder := httptest.NewRecorder()
	raven := &wrapServer{}
	wrap := NewErrorWrap(raven)
	router := httprouter.New()
	handler := negroni.New(negroni.Wrap(router))

	router.GET("/hello-not-found", wrap.Do(testHelloNotFound))

	req, _ := http.NewRequest("GET", "/hello-not-found", nil)
	handler.ServeHTTP(recorder, req)

	util.Expect(t, recorder.Code, http.StatusNotFound)
	util.Expect(t, strings.TrimSpace(recorder.Body.String()), `{"error":"Not found","error_code":"not-found"}`)
	util.Expect(t, len(raven.Msgs), 0)
}

func TestErrorWrapInternalError(t *testing.T) {
	recorder := httptest.NewRecorder()
	raven := &wrapServer{}
	wrap := NewErrorWrap(raven)
	router := httprouter.New()
	handler := negroni.New(negroni.Wrap(router))

	router.GET("/hello-internal-error", wrap.Do(testHelloInternalError))

	req, _ := http.NewRequest("GET", "/hello-internal-error", nil)
	handler.ServeHTTP(recorder, req)

	util.Expect(t, recorder.Code, http.StatusInternalServerError)
	util.Expect(t, strings.TrimSpace(recorder.Body.String()), `{"error":"Database error","error_code":"error-select"}`)
	util.Refute(t, len(raven.Msgs), 0)
}

func testHelloOK(w http.ResponseWriter, r *http.Request, p httprouter.Params) *HandledError {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello World!"))
	return nil
}

func testHelloNotFound(w http.ResponseWriter, r *http.Request, p httprouter.Params) *HandledError {
	err := errors.New("not-found example error")
	return &HandledError{err, 404, "Not found", "not-found"}
}

func testHelloInternalError(w http.ResponseWriter, r *http.Request, p httprouter.Params) *HandledError {
	err := errors.New("error-500 example error")
	return &HandledError{err, 500, "Database error", "error-select"}
}
