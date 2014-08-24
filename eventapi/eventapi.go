package eventapi

import (
	s "github.com/agoravoting/authapi/server"
	"github.com/agoravoting/authapi/middleware"
	"github.com/julienschmidt/httprouter"
	"github.com/codegangsta/negroni"
	"net/http"
)

const (
	SESSION_EXPIRE = 3600
)

type EventApi struct {
	router *httprouter.Router
	name string
}

func (ea *EventApi) Name() string {
	return ea.name;
}

func (ea *EventApi) Init() (err error) {
	// setup the routes
	ea.router = httprouter.New()
	ea.router.GET("/", middleware.Join(ea.get,
		s.Server.CheckPerms("superuser", SESSION_EXPIRE)))

	ea.router.GET("/:id", middleware.Join(ea.get,
		s.Server.CheckPerms("(superuser|admin-auth-event-${id})", SESSION_EXPIRE)))

	// add the routes to the server
	handler := negroni.New(negroni.Wrap(ea.router))
	s.Server.Mux.OnMux("api/v1/event", handler)
	return
}

func (ea *EventApi) get(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello world!"))
}

// add the modules to available modules on startup
func init() {
	s.Server.AvailableModules = append(s.Server.AvailableModules, &EventApi{name: "github.com/agoravoting/authapi/eventapi"})
}
