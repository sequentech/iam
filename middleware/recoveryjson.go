package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"fmt"
)

const (
	PANIC_LOG_FMT = "PANIC %s\n%s"
	JSON_MIMETYPE = "application/json"
)

// RecoveryJSON is a Negroni middleware that recovers from any panics and writes a 500 if there was one.
type RecoveryJson struct {
	Logger *log.Logger
}

type ErrorJson struct {
	Error string `json:"error"`
}

func NewErrorJson(err interface{}) *ErrorJson {
	return &ErrorJson{fmt.Sprintf("%v", err)}
}

// NewRecoveryJson returns a new instance of RecoveryJson
func NewRecoveryJson(Logger *log.Logger) *RecoveryJson {
	return &RecoveryJson{Logger: Logger}
}

func (rec *RecoveryJson) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func() {
		if err := recover(); err != nil {
			w.Header().Set("Content-Type", JSON_MIMETYPE)
			w.WriteHeader(http.StatusInternalServerError)
			rec.Logger.Printf(PANIC_LOG_FMT, err, debug.Stack())
			content, err := json.Marshal(NewErrorJson(err))
			if err != nil {
				panic(err)
			}
			w.Write(content)
		}
	}()
	next(w, r)
}
