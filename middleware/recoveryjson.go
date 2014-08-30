package middleware

import (
	"fmt"
	"github.com/agoravoting/authapi/util"
	"log"
	"net/http"
	"runtime/debug"
)

const (
	PANIC_LOG_FMT = "PANIC %s\n%s"
	JSON_MIMETYPE = "application/json"
)

// RecoveryJSON is a Negroni middleware that recovers from any panics and writes a 500 if there was one.
type RecoveryJson struct {
	Logger *log.Logger
	Raven  RavenClientIface
}

type errorJson struct {
	Error string `json:"error"`
}

func newErrorJson(err interface{}) *errorJson {
	return &errorJson{fmt.Sprintf("%v", err)}
}

// NewRecoveryJson returns a new instance of RecoveryJson
func NewRecoveryJson(logger *log.Logger, raven RavenClientIface) *RecoveryJson {
	return &RecoveryJson{Logger: logger, Raven: raven}
}

func (rec *RecoveryJson) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func() {
		if err := recover(); err != nil {
			w.Header().Set("Content-Type", JSON_MIMETYPE)
			w.WriteHeader(http.StatusInternalServerError)

			msg := fmt.Sprintf(PANIC_LOG_FMT, err, debug.Stack())
			rec.Logger.Print(msg)
			if rec.Raven != nil {
				rec.Raven.CaptureMessage(msg)
			}
			content, err := util.JsonSortedMarshal(newErrorJson(err))
			if err != nil {
				panic(err)
			}
			w.Write(content)
		}
	}()
	next(w, r)
}
