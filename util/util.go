package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"
)

// Contents reads a file into a string
func Contents(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close() // f.Close will run when we're finished.

	var result []byte
	buf := make([]byte, 100)
	for {
		n, err := f.Read(buf[0:])
		result = Append(result, buf[0:n])
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err // f will be closed if we return here.
		}
	}
	return string(result), nil // f will be closed if we return here.
}

// Append bytes to a slice
func Append(slice, data []byte) []byte {
	l := len(slice)
	if l+len(data) > cap(slice) { // reallocate
		// Allocate double what's needed, for future growth.
		newSlice := make([]byte, (l+len(data))*2)
		// The copy function is predeclared and works for any slice type.
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0 : l+len(data)]
	for i, c := range data {
		slice[l+i] = c
	}
	return slice
}

// Generates an HMAC using SHA256
func GenerateMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	ret := make([]byte, 64)
	hex.Encode(ret, mac.Sum(nil))
	return ret
}

// CheckMAC returns true if messageMAC is a valid HMAC tag for message. Uses SHA256.
func CheckMAC(message, messageMAC, key []byte) bool {
	expectedMAC := GenerateMAC(message, key)

	// careful! use hmac.Equal to be safe against timing side channel attacks
	return hmac.Equal(messageMAC, expectedMAC)
}

// given an http reponse object and a sql result, returns in json the id of
// the new object inside the result
func WriteIdJson(w http.ResponseWriter, id int) (err error) {
	json_id, err := json.Marshal(map[string]interface{}{"id": id})
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusAccepted)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json_id)
	return
}

/* Test Helpers */
func Expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected '%v' (type %v) - Got '%v' (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func Refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect '%v' (type %v) - Got '%v' (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

// Marhsaller is any object that allows to marshal itself into JSON
type Marhsaller interface {
	Marshal() ([]byte, error)
}

// JsonMarshalOne prints any marshaller into the response.
// NOTE: if m.Marshall() fails, it panics.
func JsonMarshalOne(w http.ResponseWriter, m Marhsaller) {
	var (
		data []byte
		err  error
	)

	w.Header().Set("Content-Type", "content/json")
	if data, err = m.Marshal(); err != nil {
		panic(err)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// JsonSortedMarshal sorts map keys so that the resulting bytes is reproducible.
// This can be useful if you for example are going to hash the marshalled string.
// Currently, this is already done by encoding/json marshaller.
func JsonSortedMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
