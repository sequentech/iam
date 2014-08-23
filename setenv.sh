#!/bin/bash

export GOPATH=`godep path`:$GOPATH
export PATH="$PATH:`godep path`/bin"
[ -d "$GOPATH" ] || mkdir -p $GOPATH
