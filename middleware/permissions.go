package middleware

import (
	"github.com/agoravoting/authapi/util"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"strings"
	"strconv"
	"time"
	"regexp"
	"os"
)

// struct that stores information about the checkPerms
type checkPerms struct {
	secret []byte
	expire_secs int
	perm string
}

/*
 CheckPerms is a middleware that checks that an HMAC with a specific permissions
 string is valid.

 The HMAC is read from the "Authorization" header, with data separated with
 semicolons. Here's an example:

 Authorization: superadmin:3434380554:deadbeefdeadbeefdeadbeefdeadbeef

  * First field indicates the granted permission string: "superadmin"
  * The second field is the timestamp: "3434380554"
  * The third field is the hash of the hmac: "deadbeefdeadbeefdeadbeefdeadbeef"

 */
func CheckPerms(perm string, secret string, expire_secs int) (obj *checkPerms) {
	obj = &checkPerms{perm: perm, secret: []byte(secret), expire_secs: expire_secs}
	return
}

func (rec *checkPerms) ServeHTTP(w http.ResponseWriter, r *http.Request, p httprouter.Params, next httprouter.Handle) {
	var (
		fields = strings.Split(r.Header.Get("Authorization"), ":")
		l = len(fields)
		timestamp int64
		err error
	)

	// check hmac and santize fields
	if l < 3 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	message := []byte(strings.Join(fields[:l-1], ":"))
	messageMAC := []byte(fields[l-1])
	if !util.CheckMAC(message, messageMAC, rec.secret) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// check timestamp is still valid
	if timestamp, err = strconv.ParseInt(fields[l-2], 10, 32); err !=  nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if int64(time.Now().Unix()) - timestamp >= int64(rec.expire_secs) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// expand params
	required_perm := os.Expand(rec.perm, func(str string) string {
		return p.ByName(str)
	})

	// compile regexp
	rx, err := regexp.Compile("^" + required_perm + "$")
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

	// checks if any of the permissions suffices
	//
	// NOTE: constant time comparison is not needed because what is permission
	// needed will be public anyway and the incoming string has been already
	// authenticated with the HMAC. If it was needed, we wouldn't allow regexps,
	// as there's currently no easy way to do constant time comparison with
	// them.
	if !rx.MatchString(fields[0]) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	next(w, r, p)
}

// Given a secret and a perm string, generates a valid content for
// the Authorization header
func AuthHeader(perm string, secret string) string {
	msg := perm + ":" + strconv.FormatInt(time.Now().Unix(), 10)
	MAC := string(util.GenerateMAC([]byte(msg), []byte(secret)))

	return msg + ":" + MAC
}
