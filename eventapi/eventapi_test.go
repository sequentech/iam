package eventapi

import (
	"fmt"
	"net/http"
	"testing"
	stest "github.com/agoravoting/authapi/server/testing"
	"github.com/agoravoting/authapi/middleware"
)

const (
	newEvent = `{
	"name": "foo election",
	"auth_method": "sms-code",
	"auth_method_config": {
		"probando": "lo que sea"
	}
}`
	secret = "somesecret"
)

func TestEventApi(t *testing.T) {
	ts := stest.New(t)
	defer ts.TearDown()
	auth_admin := map[string]string{"Authorization": middleware.AuthHeader("superuser", stest.SharedSecret)}

	// do a post and get it back
	ret := ts.Request("POST", "/api/v1/event/", http.StatusAccepted, auth_admin, newEvent)
	fmt.Printf("what-req-out = %s\n", ret)
	ret = ts.Request("GET", "/api/v1/event/1", http.StatusAccepted, auth_admin, "")
	fmt.Printf("req-out = %s\n", ret)

}
