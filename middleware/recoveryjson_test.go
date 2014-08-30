package middleware

import (
	"strings"
	"bytes"
	"github.com/agoravoting/authapi/util"
	"github.com/codegangsta/negroni"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recoveryServer is a test type used for testing the ErrorWrap Raven handling
type recoveryServer struct {
	Msgs string
}

// RavenClient implements middleware.Ravenable, needed for the middleware
func (s *recoveryServer) RavenClient() RavenClientIface {
	return s
}

// CaptureMessage registers in Msgs the last captured message
func (s *recoveryServer) CaptureMessage(msgs ...string) (id string, err error) {
	s.Msgs = strings.Join(msgs, ";")
	return "1", nil
}

func TestRecoveryJson(t *testing.T) {
	buff := bytes.NewBufferString("")
	recorder := httptest.NewRecorder()
	recServer := &recoveryServer{}
	rec := NewRecoveryJson(log.New(buff, "[recoveryjson] ", 0), recServer)

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
	util.Refute(t, len(recServer.Msgs), 0)
}
