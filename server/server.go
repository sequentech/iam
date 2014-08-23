package server

/* Creates the http server, with the routes etc
*/

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/agoravoting/authapi/middleware"
	"github.com/agoravoting/authapi/util"
	"github.com/codegangsta/negroni"
	"github.com/imdario/medeina"
	"encoding/json"
	"log"
	"os"
)

// structure that holds important data related to the webserver, all in one place
type server struct {
	DbMaxIddleConnections int
	DbConnectString string
	SharedSecret string
	Admins []string
	Debug bool

	Logger *log.Logger
	Http *negroni.Negroni
	Mux *medeina.Medeina
	Db *sqlx.DB
	ModulesInit []func()
}
// global server inside this variable
var Server server

// initServer initializes the global Server variable. Should be called only once.
func (s *server) Init(confPath string) (err error) {
	s.Logger = log.New(os.Stdout, "[authapi] ", 0)
	s.Mux = medeina.NewMedeina()

	// parse config
	confStr, err := util.Contents(confPath)
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(confStr), &s)
	if err != nil {
		return
	}

	// configure database
	s.DbConnectString = os.ExpandEnv(s.DbConnectString)
	s.Logger.Print("connecting to postgres: " + s.DbConnectString)
    s.Db, err = sqlx.Connect("postgres", s.DbConnectString)
    if err != nil {
        return
    }
	s.Db.SetMaxIdleConns(s.DbMaxIddleConnections)

	// construct the http server
	s.Http = negroni.Classic()
	s.Http.Use(negroni.NewRecovery())
	s.Http.Use(middleware.NewRecoveryJson())
	if s.Debug {
		s.Logger.Print("In debug mode")
		s.Http.Use(negroni.NewLogger())
	}
	s.Http.UseHandler(s.Mux)

	// init modules, only once the server instance has been configured
	for _, init_func := range s.ModulesInit {
		init_func()
	}

	return
}
