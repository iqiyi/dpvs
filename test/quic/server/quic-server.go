package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"

	quic "github.com/quic-go/quic-go"

	"quic-test/pkg/uoa"
)

var servAddr = ":4242"

var keyLogFile = "quic-go-server-sshkey.log"

func main() {
	if len(os.Args) > 1 {
		servAddr = os.Args[1]
	}
	fmt.Printf("Quic Server listens on %s\n", servAddr)

	keyLog, err := os.Create(keyLogFile)
	if err != nil {
		log.Fatal(err)
	}
	defer keyLog.Close()

	tlsConf := generateTLSConfig()
	tlsConf.KeyLogWriter = keyLog

	/*
		listener, err := quic.ListenAddr(servAddr, tlsConf, nil)
		if err != nil {
			panic(err)
		}
	*/
	udpAddr, err := net.ResolveUDPAddr("udp", servAddr)
	if err != nil {
		panic(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	listener, err := (&quic.Transport{
		Conn: udpConn,
	}).Listen(tlsConf, nil)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	ctx := context.Background()
	for {
		sess, err := listener.Accept(ctx)
		if err != nil {
			panic(err)
		}
		go handleSession(ctx, udpConn, sess)
	}
}

func handleSession(ctx context.Context, udpConn *net.UDPConn, sess quic.Connection) {
	file, err := udpConn.File()
	if err != nil {
		panic(err)
	}
	uoaAddr, err := uoa.GetUoaAddr(file.Fd(), sess.RemoteAddr(), sess.LocalAddr())
	if err != nil {
		fmt.Printf("New connection from %v, uoaAddr failed for %v\n", sess.RemoteAddr(), err)
	} else {
		fmt.Printf("New connection from %v, uoaAddr %v\n", sess.RemoteAddr(), uoaAddr)
	}
	stream, err := sess.AcceptStream(ctx)
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	fmt.Printf("accepted new conn stream: %v\n", stream.StreamID())

	// the server simply echo the received data back to client
	buffer := make([]byte, 32)
	_, err = stream.Read(buffer)
	if err != nil {
		panic(err)
	}
	fmt.Printf("got data: %s\n", buffer)

	buffer = []byte("Hello, QUIC Client!")
	_, err = stream.Write(buffer)
	if err != nil {
		panic(err)
	}
	fmt.Printf("sent data: %s\n", buffer)
}

// generateTLSConfig creates TLS configs required for TLS handshake.
// In fact, you should use an authorized certificate released from CA.
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	template.Subject = pkix.Name{Organization: []string{"quic-go"}}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
