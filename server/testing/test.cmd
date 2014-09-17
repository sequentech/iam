cd %GOPATH%\src\github.com\agoravoting\authapi
goose -env test up
godep go test github.com/agoravoting/authapi/eventapi
goose -env test down