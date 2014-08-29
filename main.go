package main

import (
	_ "bitbucket.org/liamstask/goose/lib/goose"
	_ "github.com/agoravoting/authapi/eventapi"
	s "github.com/agoravoting/authapi/server"

	"flag"
	"os"
	"os/signal"
)

var quit = make(chan bool)

// Init allows to send a terminate signal to the process to finish it
func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			quit <- true
		}
	}()
}

func main() {
	var (
		err error
	)

	var addr = flag.String("addr", ":3000", "http service address")
	var conf = flag.String("config", "config.json", "path to the config file")
	flag.Parse()
	if err = s.Server.Init(*conf); err != nil {
		panic(err)
	}

	go s.Server.Http.Run(*addr)
	<-quit
}
