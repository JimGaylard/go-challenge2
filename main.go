package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

var nonce *[24]byte

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
	Reader io.Reader
	Pub    *[32]byte
	Priv   *[32]byte
}

func (r *secureReader) Read(p []byte) (n int, err error) {
	out := make([]byte, 32)

	fmt.Printf("p: %s\n", string(p))
	decrypted, done := box.Open(out, p, nonce, r.Pub, r.Priv)
	if done == false {
		fmt.Println("box.Open reports false\n")
		fmt.Printf("out: %s\n", string(out))
		fmt.Printf("decrypted: %s\n", string(decrypted))
	}

	n, err = r.Reader.Read(decrypted)
	if err != nil {
		log.Fatal(err)
	}

	return
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sr := &secureReader{
		Reader: r,
		Pub:    pub,
		Priv:   priv,
	}

	return sr
}

func newNonce() (*[24]byte, error) {
	var nonce [24]byte
	slice := nonce[:]

	if _, err := rand.Reader.Read(slice); err != nil {
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
