package middleware

import (
	"bytes"
	"reflect"
	"log"
	"net/http"
	"net/http/httptest"
	"github.com/codegangsta/negroni"
	"testing"
)

func TestRecovery(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()

	rec := NewRecoveryJson(log.New(buff, "[recoveryjson] ", 0))

	n := negroni.New()
	// replace log for testing
	n.Use(rec)
	n.UseHandler(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		panic(`some error`)
	}))
	n.ServeHTTP(recorder, (*http.Request)(nil))
	expect(t, recorder.Code, http.StatusInternalServerError)
	refute(t, recorder.Body.Len(), 0)
	refute(t, len(buff.String()), 0)
}


/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}