package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"syscall"

	quic "github.com/quic-go/quic-go"

	"quic-test/pkg/cid"
	"quic-test/pkg/uoa"
)

var (
	hostIP net.IP
)

func init() {
	if hostIP, _ = cid.FindLocalIP(""); hostIP == nil {
		hostIP = net.IPv4(127, 0, 0, 1)
	}
	fmt.Println("Host IP:", hostIP)
}

func main() {
	servAddr := flag.String("server", ":4242", "server listener address")
	keyLogFile := flag.String("keylog", "", "key log file")
	uoaCliAddr := flag.Bool("uoa", true, "enable uoa client address")
	flag.Parse()

	fmt.Printf("Quic Server listens on %s (uoa client address %v)\n", *servAddr, *uoaCliAddr)

	tlsConf := generateTLSConfig()
	if *keyLogFile != "" {
		keyLog, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer keyLog.Close()
		tlsConf.KeyLogWriter = keyLog
	}

	cidGenerator := cid.NewDpvsQCID(10, 4, 0, hostIP, 0)

	/*
		listener, err := quic.ListenAddr(*servAddr, tlsConf, nil)
		if err != nil {
			panic(err)
		}
	*/
	udpAddr, err := net.ResolveUDPAddr("udp", *servAddr)
	if err != nil {
		panic(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	listener, err := (&quic.Transport{
		Conn:                  udpConn,
		ConnectionIDGenerator: cidGenerator,
	}).Listen(tlsConf, nil)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	var uoaConn *net.UDPConn
	if *uoaCliAddr {
		uoaConn = udpConn
	}

	ctx := context.Background()
	for {
		sess, err := listener.Accept(ctx)
		if err != nil {
			panic(err)
		}
		go handleSession(ctx, uoaConn, sess)
	}
}

func handleSession(ctx context.Context, udpConn *net.UDPConn, sess quic.Connection) {
	if udpConn != nil {
		file, err := udpConn.File()
		if err != nil {
			panic(err)
		}
		defer file.Close()

		// FIXME: Even though the file is an duplicate from the original udpConn.
		// a just single call to file.Fd() blocks the quic session noticeably when
		// using the default blocking mode. Having no idea about the cause of this
		// problem, just set the fd to be nonblock, hoping without other influences.
		fd := file.Fd()
		syscall.SetNonblock(int(fd), true)

		uoaAddr, err := uoa.GetUoaAddr(fd, sess.RemoteAddr(), sess.LocalAddr())
		if err != nil {
			fmt.Printf("New connection from %v, uoaAddr failed for %v\n", sess.RemoteAddr(), err)
		} else {
			fmt.Printf("New connection from %v, uoaAddr %v\n", sess.RemoteAddr(), uoaAddr)
		}
	} else {
		fmt.Printf("New connection from %v\n", sess.RemoteAddr())
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
