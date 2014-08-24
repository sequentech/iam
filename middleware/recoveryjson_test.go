package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"github.com/codegangsta/negroni"
	"github.com/agoravoting/authapi/util"
	"testing"
)

func TestRecoveryJson(t *testing.T) {
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
	util.Expect(t, recorder.Code, http.StatusInternalServerError)
	util.Refute(t, recorder.Body.Len(), 0)
	util.Refute(t, len(buff.String()), 0)
}