## Install ##

### Setup the database ###

* Postgresql
* Create the database:
    * createuser -P authapi
    * createdb -O authapi authapi
* go get bitbucket.org/liamstask/goose/cmd/goose
* $ goose up

### Godep ###

* export GOPATH=$(godep path):$PWD
* export GOBIN=$(godep path)/bin
* godep restore
* godep go build
* godep go install

#### Known errors ####

* main.go:5:2: cannot find package "github.com/agoravoting/authapi/eventapi" in any of:
This happens because godep search for packages in the GOPATH/src directory
with the import folder estructure. How to fix?

$ mkdir -p src/github.com/agoravoting/
$ cd src/github.com/agoravoting/
$ ln -s ../../../ authapi
$ cd -
$ godep go build

### Run ###

* godep go run main.go
* ./authapi
