package middleware

import (
	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var standard http.Handler

const secret = "some secret"

func init() {
	standard = loadStandard()
}

func loadStandard() http.Handler {
	mux := httprouter.New()
	mux.GET("/hello", hello)

	mux.GET("/admin/hello", Join(hello, CheckPerms("admin", secret, 1)))

	mux.GET("/user/:id/hello", Join(hello, CheckPerms("user-$id", secret, 1)))

	mux.GET("/useroradmin/:id/hello", Join(hello, CheckPerms("(admin|user-$id)", secret, 10)))

	return negroni.New(negroni.Wrap(mux))
}

func hello(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.WriteHeader(http.StatusOK)
}

func TestHandlers(t *testing.T) {
	noauth := map[string]string{}
	auth_admin := map[string]string{"Authorization": AuthHeader("admin", secret)}
	auth_user1 := map[string]string{"Authorization": AuthHeader("user-1", secret)}
	invalid_auth1 := map[string]string{"Authorization": "aa:bb:cc"}
	invalid_auth2 := map[string]string{"Authorization": "whatever"}

	testRequests(t, "GET", "/hello", http.StatusOK, noauth)
	testRequests(t, "GET", "/hello", http.StatusOK, invalid_auth1)
	testRequests(t, "GET", "/hello", http.StatusOK, invalid_auth2)
	testRequests(t, "GET", "/hello", http.StatusOK, auth_admin)
	testRequests(t, "GET", "/hellox", http.StatusNotFound, noauth)
	testRequests(t, "GET", "/admin/hello", http.StatusUnauthorized, noauth)
	testRequests(t, "GET", "/admin/hello", http.StatusUnauthorized, invalid_auth1)
	testRequests(t, "GET", "/admin/hello", http.StatusUnauthorized, invalid_auth2)
	testRequests(t, "GET", "/user/1/hello", http.StatusUnauthorized, noauth)
	testRequests(t, "GET", "/user/2/hello", http.StatusUnauthorized, noauth)
	testRequests(t, "GET", "/useroradmin/1/hello", http.StatusUnauthorized, noauth)

	testRequests(t, "GET", "/admin/hello", http.StatusOK, auth_admin)
	testRequests(t, "GET", "/user/1/hello", http.StatusOK, auth_user1)
	testRequests(t, "GET", "/user/1/hello", http.StatusUnauthorized, auth_admin)
	testRequests(t, "GET", "/user/2/hello", http.StatusUnauthorized, auth_admin)
	testRequests(t, "GET", "/useroradmin/1/hello", http.StatusOK, auth_user1)
	testRequests(t, "GET", "/useroradmin/2/hello", http.StatusUnauthorized, auth_user1)
	testRequests(t, "GET", "/useroradmin/1/hello", http.StatusOK, auth_admin)

	time.Sleep(1100 * time.Millisecond)

	testRequests(t, "GET", "/admin/hello", http.StatusUnauthorized, auth_admin)
	testRequests(t, "GET", "/user/1/hello", http.StatusUnauthorized, auth_user1)
	testRequests(t, "GET", "/useroradmin/1/hello", http.StatusOK, auth_user1)
	testRequests(t, "GET", "/useroradmin/1/hello", http.StatusOK, auth_admin)
}

func testRequests(t *testing.T, method, path string, expectedStatus int, headers map[string]string) {
	r, _ := http.NewRequest(method, path, nil)
	w := new(httptest.ResponseRecorder)
	u := r.URL
	r.RequestURI = u.RequestURI()
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	standard.ServeHTTP(w, r)
	if w.Code != expectedStatus {
		t.Errorf("Expected %d for route %s %s found: Code=%d, Headers=%v", expectedStatus, method, u, w.Code, headers)
		panic(t)
	}
}
