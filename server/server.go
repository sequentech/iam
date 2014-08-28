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
	// settings loaded from the json config file
	DbMaxIddleConnections int
	DbConnectString string // expanded using os.ExpandEnv
	SharedSecret string
	Admins []string
	ActiveModules []string
	Debug bool
	Initialized bool // denotes if the server has already been initialized

	Logger *log.Logger
	Http *negroni.Negroni
	Mux *medeina.Medeina
	Db *sqlx.DB
	AvailableModules []Module
}
// global server inside this variable
var Server server

type Module interface {
	Name() string
	Init() error
}

// initServer initializes the global Server variable. Should be called only once: after the first call, it does nothing
func (s *server) Init(confPath string) (err error) {
	// do not let be Initialized multiple times
	if s.Initialized {
		return
	}
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
	s.Http.Use(middleware.NewRecoveryJson(s.Logger))
	if s.Debug {
		s.Logger.Print("In debug mode")
		s.Http.Use(negroni.NewLogger())
	}
	s.Http.UseHandler(s.Mux)

	// init modules, only once the server instance has been configured, and
	// only those modules that user wants to activate
	ModulesLoop:
		for _, module := range s.AvailableModules {
			var (
				mod_name = module.Name()
			)
			// find the module, and init it if found
			for _, active_module := range s.ActiveModules {
				if mod_name != active_module {
					continue
				}
				s.Logger.Print("Loading module: " + mod_name)
				if err = module.Init(); err != nil {
					s.Logger.Fatal(err)
				}
				continue ModulesLoop
			}
		}

	s.Initialized = true
	return
}

func (s *server) CheckPerms(perm string, expire_secs int) middleware.Handler {
	return middleware.CheckPerms(perm, s.SharedSecret, expire_secs)
}
