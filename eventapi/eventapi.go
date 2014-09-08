package eventapi

import (
	"github.com/agoravoting/authapi/middleware"
	s "github.com/agoravoting/authapi/server"
	"github.com/agoravoting/authapi/util"
	"github.com/codegangsta/negroni"
	"github.com/jmoiron/sqlx"
	"github.com/julienschmidt/httprouter"
	// 	"net/http/httputil"
	"encoding/json"
	"net/http"
	"strconv"
)

const (
	SESSION_EXPIRE = 3600
)

type EventApi struct {
	router *httprouter.Router
	name   string

	insertStmt *sqlx.NamedStmt
	getStmt    *sqlx.Stmt
	delStmt    *sqlx.Stmt
}

func (ea *EventApi) Name() string {
	return ea.name
}

func (ea *EventApi) Init() (err error) {
	// setup the routes
	ea.router = httprouter.New()
	ea.router.GET("/", middleware.Join(
		s.Server.ErrorWrap.Do(ea.list),
		s.Server.CheckPerms("superuser", SESSION_EXPIRE)))
	ea.router.POST("/", middleware.Join(
		s.Server.ErrorWrap.Do(ea.post),
		s.Server.CheckPerms("superuser", SESSION_EXPIRE)))

	ea.router.GET("/:id", middleware.Join(
		s.Server.ErrorWrap.Do(ea.get),
		s.Server.CheckPerms("(superuser|admin-auth-event-${id})", SESSION_EXPIRE)))
	ea.router.DELETE("/:id", middleware.Join(
		s.Server.ErrorWrap.Do(ea.delete),
		s.Server.CheckPerms("superuser", SESSION_EXPIRE)))

	// setup prepared sql queries
	if ea.insertStmt, err = s.Server.Db.PrepareNamed("INSERT INTO event (name, auth_method, auth_method_config) VALUES (:name, :auth_method, :auth_method_config) RETURNING id"); err != nil {
		return
	}

	if ea.getStmt, err = s.Server.Db.Preparex("SELECT * FROM event WHERE id = $1"); err != nil {
		return
	}

	if ea.delStmt, err = s.Server.Db.Preparex("DELETE FROM event WHERE id = $1"); err != nil {
		return
	}

	// add the routes to the server
	handler := negroni.New(negroni.Wrap(ea.router))
	s.Server.Mux.OnMux("api/v1/event", handler)
	return
}

// lists the available events
func (ea *EventApi) list(w http.ResponseWriter, r *http.Request, _ httprouter.Params) *middleware.HandledError {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello world!"))
	return nil
}

// returns an event
func (ea *EventApi) get(w http.ResponseWriter, r *http.Request, p httprouter.Params) *middleware.HandledError {
	var (
		e   []Event
		err error
		id  int64
	)

	id, err = strconv.ParseInt(p.ByName("id"), 10, 32)
	if err != nil || id <= 0 {
		return &middleware.HandledError{Err: err, Code: 400, Message: "Invalid id format", CodedMessage: "invalid-format"}
	}

	if err = ea.getStmt.Select(&e, id); err != nil {
		return &middleware.HandledError{Err: err, Code: 500, Message: "Database error", CodedMessage: "error-select"}
	}

	if len(e) == 0 {
		return &middleware.HandledError{Err: err, Code: 404, Message: "Not found", CodedMessage: "not-found"}
	}

	b, err := e[0].Marshal()
	if err != nil {
		return &middleware.HandledError{Err: err, Code: 500, Message: "Error marshalling the data", CodedMessage: "marshall-error"}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
	return nil
}

func (ea *EventApi) delete(w http.ResponseWriter, r *http.Request, p httprouter.Params) *middleware.HandledError {
	var (
		e   []Event
		err error
		id  int64
	)

	id, err = strconv.ParseInt(p.ByName("id"), 10, 32)
	if err != nil || id <= 0 {
		return &middleware.HandledError{Err: err, Code: 400, Message: "Invalid id format", CodedMessage: "invalid-format"}
	}

	if err = ea.getStmt.Select(&e, id); err != nil {
		return &middleware.HandledError{Err: err, Code: 500, Message: "Database error", CodedMessage: "error-select"}
	}

	if len(e) == 0 {
		return &middleware.HandledError{Err: err, Code: 404, Message: "Not found", CodedMessage: "not-found"}
	}

	if _, err := ea.delStmt.Exec(id); err != nil {
		return &middleware.HandledError{Err: err, Code: 500, Message: "Error deleting the data", CodedMessage: "sql-error"}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return nil
}

// parses an event from a request.
// TODO: generalize and move to utils pkg
func parseEvent(r *http.Request) (e Event, err error) {
	// 	rb, err := httputil.DumpRequest(r, true)
	if err != nil {
		return
	}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&e)
	if err != nil {
		return
	}
	return
}

// add a new event
func (ea *EventApi) post(w http.ResponseWriter, r *http.Request, _ httprouter.Params) *middleware.HandledError {
	var (
		tx    = s.Server.Db.MustBegin()
		event Event
		id    int
		err   error
	)
	event, err = parseEvent(r)
	if err != nil {
		return &middleware.HandledError{Err: err, Code: 400, Message: "Invalid json-encoded event", CodedMessage: "invalid-json"}
	}
	event_json, err := event.Json()
	if err != nil {
		return &middleware.HandledError{Err: err, Code: 500, Message: "Error re-writing the data to json", CodedMessage: "error-json-encode"}
	}

	if err = tx.NamedStmt(ea.insertStmt).QueryRowx(event_json).Scan(&id); err != nil {
		tx.Rollback()
		return &middleware.HandledError{Err: err, Code: 500, Message: "Error inserting the event", CodedMessage: "error-insert"}
	}
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return &middleware.HandledError{Err: err, Code: 500, Message: "Error comitting the event", CodedMessage: "error-commit"}
	}

	// return id
	if err = util.WriteIdJson(w, id); err != nil {
		return &middleware.HandledError{Err: err, Code: 500, Message: "Error returing the id", CodedMessage: "error-return"}
	}
	return nil
}

// add the modules to available modules on startup
func init() {
	s.Server.AvailableModules = append(s.Server.AvailableModules, &EventApi{name: "github.com/agoravoting/authapi/eventapi"})
}
