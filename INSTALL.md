# Install

## Install dependencies

Configure your go paths. To do so, first install mercurial and git. This can
be done for example in opensuse this way (in other distros will vary):

    sudo zypper install git-core mercurial

Then configure your paths and install godep:

    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$GOPATH/bin:$PATH' >> ~/.bashrc
    echo 'export GOBIN=$GOPATH/bin' >> ~/.bashrc
    source ~/.bashrc
    go get github.com/tools/godep

Once that's done, you can install dependencies, compile and install authapi:

    cd path/to/authapi
    godep restore
    godep go install

## Setup the database

The configuration of the database is setup in two places. One used for
goose, a go database migration tool placed in `authapi/db/dbconf.yml`, and the
other for the general configuration of authapi, which can be placed anywhere,
but there's a provided example `authapi/config.json`.

Here we will use the default configuration for the database for convenience,
but you should obviously do not use it (especially for the passwords) in a
production environment.

Prerequisites: install postgresql database server in your system. Then, create
the database (typically, with the postgres system user):

    su - postgres
    createuser -P authapi
    createdb -O authapi authapi

You must also have goose installed, if it is not use

godep go install bitbucket.org/liamstask/goose/cmd/goose

Then create the tables using the goose migration system:

    cd path/to/authapi
    godep goose up

If you want to run the unit tests, you'll need an additional database and user:

    createuser -P test_authapi
    createdb -O test_authapi test_authapi

## Run

* godep go run main.go
* ./authapi

## Execute unit tests

First you need to setup the test database