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
	newEvent := ts.RequestJson("POST", "/api/v1/event/", http.StatusAccepted, auth_admin, newEvent).(map[string]interface{})
	apiPath := fmt.Sprintf("/api/v1/event/%.0f", newEvent["id"])
	ts.Request("GET", apiPath, http.StatusOK, auth_admin, "")
// 	fmt.Printf("req-out = %s\n", ret)

}
