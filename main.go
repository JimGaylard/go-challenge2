package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

type secureWriter struct {
	Writer io.Writer
	Pub    *[32]byte
	Priv   *[32]byte
}

func (w *secureWriter) Write(p []byte) (n int, err error) {
	nonce, err := newNonce()
	if err != nil {
		log.Fatal(err)
	}

	out := make([]byte, 32)

	encrypted := box.Seal(out, p, nonce, w.Pub, w.Priv)

	n, err = w.Writer.Write(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	return n, err
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sw := &secureWriter{
		Writer: w,
		Pub:    pub,
		Priv:   priv,
	}

	return sw
}

type secureReader struct {
	reader io.Reader
	pub    *[32]byte
	priv   *[32]byte
}

func (r *secureReader) Read(p []byte) (n int, err error) {
	return 0, nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	msg, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	nonce, err := newNonce()
	if err != nil {
		log.Fatal(err)
	}

	out := make([]byte, 1024)

	decrypted, done := box.Open(out, msg, nonce, pub, priv)
	if done != true {
		log.Fatal("box.Open returned 'false'")
	}
	return bytes.NewReader(decrypted)
}

func newNonce() (*[24]byte, error) {
	var nonce [24]byte
	slice := nonce[:]

	if _, err := rand.Read(slice); err != nil {
		return nil, err
	}
	return &nonce, nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
