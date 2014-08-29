package testing

import (
	s "github.com/agoravoting/authapi/server"
	"os/exec"
	"net/http"
	"net/http/httptest"
	"testing"
	"io/ioutil"
	"encoding/json"
	"bytes"
)

type TestServer struct {
	t *testing.T
}

var (
	NoHeader = map[string]string{}
	SharedSecret = "somesecret"
	Config = `{
	"Debug": true,
	"DbMaxIddleConnections": 5,
	"DbConnectString": "user=test_authapi password=test_authapi dbname=test_authapi sslmode=disable",

	"SharedSecret": "somesecret",
	"Admins": ["test@example.com"],
	"ActiveModules": [
		"github.com/agoravoting/authapi/eventapi"
	],
	"RavenDSN": ""
}`
)

// initializes the test server
func New(t *testing.T) (ts *TestServer) {
	var (
		name string
	)

	// generate config file. needs to be done this way, because go test could be
	// being executed in any path and we can't assume it's anywhere
	if (!s.Server.Initialized) {
		f, _ := ioutil.TempFile("", "testfile")
		name = f.Name()
		f.Write([]byte(Config))
		f.Close()
	}

	ts = &TestServer{t: t}

	c := exec.Command("bash", "-c", "cd $GOPATH/src/github.com/agoravoting/authapi; goose -env test up")
	if _, err := c.Output(); err != nil {
		panic(err)
	}

	if err := s.Server.Init(name); err != nil {
		panic(err)
	}
	return
}

// tears down the test server
func (ts *TestServer) TearDown() {
	c := exec.Command("bash", "-c", "cd $GOPATH/src/github.com/agoravoting/authapi; goose -env test down")
	if _, err := c.Output(); err != nil {
		panic(err)
	}
}

func (ts *TestServer) Request(method, path string, expectedStatus int, headers map[string]string, requesTBody string) string {
	r, _ := http.NewRequest(method, path, bytes.NewBufferString(requesTBody))
	w := httptest.NewRecorder()
	u := r.URL
	r.RequestURI = u.RequestURI()
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	s.Server.Http.ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != expectedStatus {
		ts.t.Errorf("Expected %d for route %s %s found: Code=%d, req-Headers=%v ret-body=%s\n", expectedStatus, method, u, w.Code, headers, body)
	}

	return body
}

func (ts *TestServer) RequestJson(method, path string, expectedStatus int, headers map[string]string, requestBody string) interface{} {
	body := ts.Request(method, path, expectedStatus, headers, requestBody)
	var f interface{}
	err := json.Unmarshal([]byte(body), &f)
	if err != nil {
		ts.t.Error(err)
	}
	return f
}
