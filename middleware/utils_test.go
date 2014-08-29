package middleware

import (
	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/http/httptest"
	"testing"
)

func hello_utils(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("World"))
}

func test_middleware(w http.ResponseWriter, r *http.Request, p httprouter.Params, next httprouter.Handle) {
	w.Write([]byte("Hello!"))
	next(w, r, p)
}

func TestUtils(t *testing.T) {
	mux := httprouter.New()
	mux.GET("/no_hello", hello_utils)

	mux.GET("/one_hello", Join(hello_utils, HandlerFunc(test_middleware)))
	mux.GET("/two_hello", Join(hello_utils, HandlerFunc(test_middleware), HandlerFunc(test_middleware)))

	server := negroni.New(negroni.Wrap(mux))

	testBody(t, server, "GET", "/no_hello", http.StatusOK, "World")
	testBody(t, server, "GET", "/one_hello", http.StatusOK, "Hello!World")
	testBody(t, server, "GET", "/two_hello", http.StatusOK, "Hello!Hello!World")
}

func testBody(t *testing.T, server http.Handler, method, path string, expectedStatus int, expectedBody string) {
	r, _ := http.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	u := r.URL
	r.RequestURI = u.RequestURI()
	server.ServeHTTP(w, r)
	if w.Code != expectedStatus {
		t.Errorf("Expected %d for route %s %s found: Code=%d", expectedStatus, method, u, w.Code)
		panic(t)
	}
	if w.Body.String() != expectedBody {
		t.Errorf("Expected body %s for route %s %s found: Body=%s", expectedBody, method, u, w.Body.String())
		panic(t)
	}
}
