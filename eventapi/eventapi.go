package eventapi

import (
	s "github.com/agoravoting/authapi/server"
	"github.com/julienschmidt/httprouter"
	"github.com/codegangsta/negroni"
	"net/http"
)

type EventApi struct {
	Router *httprouter.Router
}

func New() (ea *EventApi, err error) {
	ea = &EventApi{}
	ea.Router = httprouter.New()
	ea.Router.GET("/", ea.get)
	return
}

func (ea *EventApi) get(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello world!"))
}

func init() {
	s.Server.ModulesInit = append(s.Server.ModulesInit, func() {
		var (
			err error
			ea *EventApi
			handler *negroni.Negroni
		)
		if ea, err = New(); err != nil {
			s.Server.Logger.Fatal(err)
		}
		handler = negroni.New(negroni.Wrap(ea.Router))
		s.Server.Mux.OnHandler("event", handler)
	})
}