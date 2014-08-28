package eventapi

import (
	s "github.com/agoravoting/authapi/server"
	"github.com/agoravoting/authapi/util"
	"github.com/agoravoting/authapi/middleware"
	"github.com/julienschmidt/httprouter"
	"github.com/codegangsta/negroni"
	"github.com/jmoiron/sqlx"
	"net/http/httputil"
	"encoding/json"
	"net/http"
	"strconv"
	"errors"
)

const (
	SESSION_EXPIRE = 3600
)

type EventApi struct {
	router *httprouter.Router
	name string

	insertStmt *sqlx.NamedStmt
	getStmt *sqlx.Stmt
}

func (ea *EventApi) Name() string {
	return ea.name;
}

func (ea *EventApi) Init() (err error) {
	// setup the routes
	ea.router = httprouter.New()
	ea.router.GET("/", middleware.Join(ea.list,
		s.Server.CheckPerms("superuser", SESSION_EXPIRE)))
	ea.router.POST("/", middleware.Join(ea.post,
		s.Server.CheckPerms("superuser", SESSION_EXPIRE)))

	ea.router.GET("/:id", middleware.Join(ea.get,
		s.Server.CheckPerms("(superuser|admin-auth-event-${id})", SESSION_EXPIRE)))

	// setup prepared sql queries
	if ea.insertStmt, err = s.Server.Db.PrepareNamed("INSERT INTO event (name, auth_method, auth_method_config) VALUES (:name, :auth_method, :auth_method_config) RETURNING id"); err != nil {
		return
	}

	if ea.getStmt, err = s.Server.Db.Preparex("SELECT * FROM event WHERE id = $1"); err != nil {
		return
	}

	// add the routes to the server
	handler := negroni.New(negroni.Wrap(ea.router))
	s.Server.Mux.OnMux("api/v1/event", handler)
	return
}

// lists the available events
func (ea *EventApi) list(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello world!"))
}

// returns an event
func (ea *EventApi) get(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var (
		e []Event
		err error
		id int
	)
	if id, err := strconv.ParseInt(p.ByName("id"), 10, 32); err !=  nil || id <= 0 {
		panic(errors.New("Invalid Id"))
	}

	if err = ea.getStmt.Select(&e, id); err != nil {
		panic(err)
	}

	if len(e) > 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	b, err := e[0].Marshal()
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func parseEvent(r *http.Request) (e Event) {
	rb, err := httputil.DumpRequest(r, true)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&e)
	if err != nil {
		s.Server.Logger.Println(string(rb))
		panic(err)
	}
	return
}

// add a new event
func (ea *EventApi) post(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var (
		tx = s.Server.Db.MustBegin()
		event = parseEvent(r)
		id int
	)
	event_json, err := event.Json()
	if err != nil {
		panic(err)
	}

	if err = tx.NamedStmt(ea.insertStmt).QueryRowx(event_json).Scan(&id); err != nil {
		tx.Rollback()
		panic(err)
	}
	tx.Commit()

	// return id
	if err = util.WriteIdJson(w, id); err != nil {
		panic(err)
	}
}

// add the modules to available modules on startup
func init() {
	s.Server.AvailableModules = append(s.Server.AvailableModules, &EventApi{name: "github.com/agoravoting/authapi/eventapi"})
}
