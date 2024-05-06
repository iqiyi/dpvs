package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/quic-go/quic-go"
)

var servAddr = ":4242"

var keyLogFile = "quic-go-client-sshkey.log"

func main() {
	if len(os.Args) > 1 {
		servAddr = os.Args[1]
	}
	fmt.Printf("target server: %s\n", servAddr)

	keyLog, err := os.OpenFile(keyLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer keyLog.Close()

	ctx := context.Background()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
		KeyLogWriter:       keyLog,
	}

	/*
		conn, err := quic.DialAddr(ctx, servAddr, tlsConf, nil)
		if err != nil {
			log.Fatal("Cannot dial QUIC server:", err)
		}
		defer conn.CloseWithError(0, "")
	*/

	serverAddr, err := net.ResolveUDPAddr("udp", servAddr)
	if err != nil {
		log.Fatal("ServerAddr resolution fail:", err)
	}

	listenAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	listener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Fatal("Listener creation falil:", err)
	}
	defer listener.Close()

	conn, err := quic.Dial(ctx, listener, serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal("Cannot dial QUIC server:", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatal("Cannot open QUIC stream:", err)
	}
	defer stream.Close()

	message := []byte("Hello, QUIC Server!")
	_, err = stream.Write(message)
	if err != nil {
		log.Fatal("Cannot write to QUIC stream:", err)
	}

	buffer := make([]byte, len(message))
	_, err = io.ReadFull(stream, buffer)
	if err != nil {
		log.Fatal("Cannot read from QUIC stream:", err)
	}

	fmt.Printf("Server says: %s\n", buffer)

	// TODO: Support connection migration.
	//  Awaiting quic-go support the feature https://github.com/quic-go/quic-go/issues/3990.
}
