package util

import (
	"io/ioutil"
	"testing"
)

func TestContents(t *testing.T) {
	f, _ := ioutil.TempFile("", "testfile")
	data := "Hello World!\n"
	name := f.Name()

	f.Write([]byte(data))
	f.Close()
	contents, _ := Contents(name)

	Expect(t, contents, data)
}

func TestAppend(t *testing.T) {
	hello := []byte("Hello ")
	world := []byte("World!")
	helloworld := "Hello World!"
	Expect(t, string(Append(hello, world)), helloworld)
}

func TestGenerateMAC(t *testing.T) {
	message := []byte("hi there!")
	key := []byte("el pastel está en el horno")
	MAC := "180523b0882e098aee998297d05ec3af35fa7df8240b596ba020ff4275f1a806"

	Expect(t, string(GenerateMAC(message, key)), MAC)
}

func TestCheckMAC(t *testing.T) {
	message := []byte("hi there!")
	key := []byte("el pastel está en el horno")
	MAC := []byte("180523b0882e098aee998297d05ec3af35fa7df8240b596ba020ff4275f1a806")

	Expect(t, CheckMAC(message, MAC, key), true)
}
