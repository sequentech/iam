# Install

You should know first how the Go ecosystem works. All code should directly
reside in $GOPATH/src. So for example, you should download and use the authapi
source in $GOPATH/src/github.com/agoravoting/authapi. This is important, 
because otherwise it will create problems with dependencies.

## Install dependencies

Configure your go paths. You can execute these commands manually and add them
to ~/.bashrc for convenience:

    export GOPATH=$(godep path):$GOPATH
    export GOBIN=$(godep path)/bin

Once that's done, you can install dependencies, compile and install authapi:

    cd path/to/authapi
    godep restore
    godep go install

## Setup the database

Prerequisites: install postgresql database server in your system. Then, create
the database (typically, with the postgres system user):

    su - postgres
    createuser -P authapi
    createdb -O authapi authapi

Note that the configuration of the database is setup in two places, 

Then create the tables using the goose migration system:

    cd path/to/authapi
    goose up

If you want to run the unit tests, you'll need an additional database and user:

    createuser -P authapi
    createdb -O authapi authapi    

## Run

* godep go run main.go
* ./authapi

## Execute unit tests

First you need to setup the test database