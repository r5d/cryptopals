// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"bufio"
	"fmt"
	"math/big"
	"net"
	"os"

	"ricketyspace.net/cryptopals/lib"
)

func C34(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: cryptopals -c 34 ENTITY PORT [S-PORT]")
		return
	}
	entity := args[0]
	if entity == "attacker" && len(args) != 3 {
		fmt.Println("Usage: cryptopals -c 34 attacker PORT S-PORT")
		return
	}
	port, err := lib.StrToNum(args[1])
	if err != nil {
		fmt.Println("Port invalid")
		return
	}
	if port < 12000 {
		fmt.Println("Error: port number must be >= 12000")
		return
	}
	sport := 0
	if entity == "attacker" {
		sport, err = lib.StrToNum(args[2])
		if err != nil {
			fmt.Println("S-Port invalid")
			return
		}
		if sport < 12000 {
			fmt.Println("Error: port number must be >= 12000")
			return
		}
	}

	// Cipher functions.
	//
	// Pack a cipher and it's iv into packet.
	cipherPacketEncode := func(cipher, iv []byte) string {
		packet := append(cipher, iv...)
		return lib.BytesToHexStr(packet)
	}
	// Unpack packet into cipher and iv.
	cipherPacketDecode := func(packet string) (cipher, iv []byte) {
		stream := lib.HexStrToBytes(packet)
		cipher = stream[0 : len(stream)-16]
		iv = stream[len(stream)-16:]

		return cipher, iv
	}
	// Encipher using AES-CBC.
	encipher := func(skey *big.Int, msg string) (string, error) {
		// Make key out of DH sesssion key.
		sha1 := lib.Sha1{}
		sha1.Init([]uint32{})
		sha1.Message(skey.Bytes())
		skeyb := sha1.Hash()
		if len(skeyb) < 16 {
			// Pad it to 16 bytes.
			skeyb = append(skeyb, make([]byte, 16-len(skeyb))...)
		}
		k := skeyb[0:16]

		// Make initialization vector.
		iv, err := lib.RandomBytes(16)
		if err != nil {
			return "", err
		}

		// Encrypt msg using AES-CBC
		cipher := lib.AESEncryptCBC([]byte(msg), k, iv)

		// Pack encrypted message in a format that can be sent
		// over the wire.
		packet := cipherPacketEncode(cipher, iv)

		// Return packed encrypted message.
		return packet, nil
	}
	// Decipher using AES-CBC.
	decipher := func(skey *big.Int, packet string) (string, error) {
		// Make key out of DH sesssion key.
		sha1 := lib.Sha1{}
		sha1.Init([]uint32{})
		sha1.Message(skey.Bytes())
		skeyb := sha1.Hash()
		if len(skeyb) < 16 {
			// Pad it to 16 bytes.
			skeyb = append(skeyb, make([]byte, 16-len(skeyb))...)
		}
		k := skeyb[0:16]

		// Decode packet
		cipher, iv := cipherPacketDecode(packet)

		// Decrypt message.
		msg, err := lib.AESDecryptCBC(cipher, k, iv)
		if err != nil {
			return "", err
		}

		return string(msg), nil
	}
	// Server handling.
	//
	// Do DH handshake with client and return DH session key.
	serverDHHandshake := func(conn net.Conn) (*big.Int, error) {
		// Read DH packet from client.
		packet, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return nil, err
		}
		// Remove newline character from packet.
		packet = packet[:len(packet)-1]

		// Try to read DH paramters from packet.
		params := lib.StrSplitAt('+', packet)
		if len(params) != 3 {
			return nil, lib.CPError{"DH paramters invalid"}
		}

		// Try make DH for this client connection.
		dh, ok := lib.NewDH(params[0], params[1])
		if !ok {
			return nil, lib.CPError{"DH initialization failed"}
		}
		// Parse client's DH public key.
		cPub, ok := new(big.Int).SetString(lib.StripSpaceChars(params[2]), 10)
		if !ok {
			return nil, lib.CPError{"DH public key invalid"}
		}

		// Send server's DH public key for this connection.
		fmt.Fprintf(conn, "%v\n", dh.Pub())

		// Return DH session key.
		return dh.SharedSecret(cPub), nil
	}
	// Handle connection from a client.
	serverHandleConn := func(conn net.Conn) {
		defer conn.Close()

		// Do DH handshake.
		skey, err := serverDHHandshake(conn)
		if err != nil {
			fmt.Printf("DH Handshake failed [%v]: %v\n",
				conn.RemoteAddr(), err)
			return
		}
		fmt.Printf("Made secure connection with %v\n", conn.RemoteAddr())

		// Enter read loop.
		for {
			packet, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				fmt.Printf("Closed connection to [%v]\n",
					conn.RemoteAddr())
				return
			}
			// Remove newline character.
			packet = packet[:len(packet)-1]

			// Decipher packet.
			msg, err := decipher(skey, packet)
			if err != nil {
				fmt.Printf("Message decryption failed for [%v]: %v\n",
					conn.RemoteAddr(), err)
				return
			}
			fmt.Printf("Received from [%v]: '%v'\n", conn.RemoteAddr(), msg)

			// Make msg to client.
			msg = fmt.Sprintf("-> %s", msg)

			// Encrypt and echo back message.
			cpacket, err := encipher(skey, msg)
			if err != nil {
				fmt.Printf("Message encryption failed for [%v]: %v\n",
					conn.RemoteAddr(), err)
				return
			}
			// Send message to client.
			fmt.Fprintf(conn, "%s\n", cpacket)
		}
	}
	// Start "secure" echo server.
	serverSpawn := func() {
		p := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", p)
		if err != nil {
			fmt.Printf("Server listen error: %v\n", err)
			return
		}
		for {
			fmt.Println("Waiting for connection...")
			conn, err := ln.Accept()
			if err != nil {
				fmt.Printf("Server accept error: %v", err)
			}
			go serverHandleConn(conn)
		}
	}
	// Client handling.
	//
	// Try to make secure connection with server using DH and
	// return server's DH public key.
	clientSecureConnToServer := func() (net.Conn, *big.Int, error) {
		// Try to connect to server.
		addr := fmt.Sprintf(":%d", port)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return conn, nil, err
		}

		// Initialize DH.
		p := lib.StripSpaceChars(
			`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                         e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                         3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                         6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                         24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                         c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                         bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                         fffffffffffff`)
		g := "2"
		dh, ok := lib.NewDH(p, g)
		if !ok {
			return conn, nil, lib.CPError{"DH initialization failed"}
		}

		// Make DH packet: p+g+pub.
		packet := fmt.Sprintf("%v+%v+%v", p, g, dh.Pub())

		// Sent DH packet to server.
		fmt.Fprintf(conn, "%s\n", packet)

		// Wait and try to get server's DH public key.
		spacket, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return conn, nil, err
		}
		// Remove newline character.
		spacket = spacket[:len(spacket)-1]

		// Parse server's DH public key.
		sPub, ok := new(big.Int).SetString(lib.StripSpaceChars(spacket), 10)
		if !ok {
			return conn, nil, lib.CPError{"Server's DH key invalid"}
		}

		// Return server connection and DH session key.
		return conn, dh.SharedSecret(sPub), nil
	}
	// Start the client.
	clientSpawn := func() {
		// Make a secure connection to server.
		conn, skey, err := clientSecureConnToServer()
		if err != nil {
			fmt.Printf("Unable to establish secure connection: %v\n", err)
			return
		}
		defer conn.Close()
		fmt.Printf("Made secure connection with %v\n", conn.RemoteAddr())

		// Enter write loop.
		for {
			// Read message from stdin.
			fmt.Printf("> ")
			msg, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				fmt.Printf("Read error: %v\n", err)
				return
			}
			// Remove newline character.
			msg = msg[:len(msg)-1]

			// Encrypt message.
			packet, err := encipher(skey, msg)
			if err != nil {
				fmt.Printf("Encryption error: %v\n", err)
				return
			}

			// Send message to server.
			fmt.Fprintf(conn, "%s\n", packet)

			// Read response from server.
			spacket, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				fmt.Printf("Server closed connection\n")
				return
			}
			// Remove newline character.
			spacket = spacket[:len(spacket)-1]

			// Decipher packet from server.
			smsg, err := decipher(skey, spacket)
			if err != nil {
				fmt.Printf("Message decryption failed: %v\n", err)
				return
			}
			// Barf server's response.
			fmt.Printf("%s\n", smsg)
		}
	}
	// Attacker handling.
	//
	// Slurp DH params from client.
	attackerSlurpDHParams := func(conn net.Conn) ([]string, error) {
		// Read DH packet from client.
		packet, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return []string{}, err
		}
		// Remove newline character from packet.
		packet = packet[:len(packet)-1]

		// Try to read DH paramters from packet.
		params := lib.StrSplitAt('+', packet)
		if len(params) != 3 {
			return []string{}, lib.CPError{"DH paramters invalid"}
		}

		// Try make a DH from params.
		_, ok := lib.NewDH(params[0], params[1])
		if !ok {
			return []string{}, lib.CPError{"DH initialization failed"}
		}
		return params, nil
	}
	// Forward initial DH request to server. Initial "parameter"
	// injection happens here (p+g+p).
	attackerConnectToServer := func(p, g string) (net.Conn, error) {
		// Try to connect to server.
		addr := fmt.Sprintf(":%d", sport)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return conn, err
		}

		// Make DH packet: p+g+p
		pub, ok := new(big.Int).SetString(lib.StripSpaceChars(p), 16)
		if !ok {
			return conn, lib.CPError{"Unable to parse p"}
		}
		packet := fmt.Sprintf("%v+%v+%v", p, g, pub)

		// Sent DH packet to server.
		fmt.Fprintf(conn, "%s\n", packet)

		// Wait and try to get server's DH public key.
		_, err = bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return conn, err
		}

		// Return server connection.
		return conn, nil
	}
	// Handle connection from a client.
	attackerHandleConn := func(conn net.Conn) {
		defer conn.Close()

		// Read DH params from client.
		dhParams, err := attackerSlurpDHParams(conn)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Forward request to server with p+g+p.
		// connServer: connection to server.
		connServer, err := attackerConnectToServer(
			dhParams[0],
			dhParams[1],
		)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer connServer.Close()

		// Respond to client with p as the public key.
		pub, ok := new(big.Int).SetString(lib.StripSpaceChars(dhParams[0]), 16)
		if !ok {
			fmt.Printf("Error: Unable to parse p\n")
			return
		}
		fmt.Fprintf(conn, "%v\n", pub)

		// Enter loop.
		skey := new(big.Int).SetInt64(0) // Session key is zero.
		for {
			// Read from client.
			packet, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				fmt.Printf("Closed connection to [%v]\n",
					conn.RemoteAddr())
				return
			}
			// Remove newline character.
			packet = packet[:len(packet)-1]

			// Decipher packet.
			msg, err := decipher(skey, packet)
			if err != nil {
				fmt.Printf("Message decryption failed for [%v]: %v\n",
					conn.RemoteAddr(), err)
				return
			}
			fmt.Printf("Received from client [%v]: '%v'\n",
				conn.RemoteAddr(), msg)

			// Encrypt and forward message to server.
			spacket, err := encipher(skey, msg)
			if err != nil {
				fmt.Printf("Message encryption failed for [%v]: %v\n",
					connServer.RemoteAddr(), err)
				return
			}
			// Send message to server.
			fmt.Fprintf(connServer, "%s\n", spacket)

			// Read encrypted message from server.
			spacket, err = bufio.NewReader(connServer).ReadString('\n')
			if err != nil {
				fmt.Printf("Closed connection to [%v]\n",
					connServer.RemoteAddr())
				return
			}
			// Remove newline character.
			spacket = spacket[:len(spacket)-1]

			// Decipher packet.
			msg, err = decipher(skey, spacket)
			if err != nil {
				fmt.Printf("Message decryption failed for [%v]: %v\n",
					connServer.RemoteAddr(), err)
				return
			}
			fmt.Printf("Received from server [%v]: '%v'\n",
				connServer.RemoteAddr(), msg)

			// Encrypt and echo back message.
			cpacket, err := encipher(skey, msg)
			if err != nil {
				fmt.Printf("Message encryption failed for [%v]: %v\n",
					conn.RemoteAddr(), err)
				return
			}
			// Send message to client.
			fmt.Fprintf(conn, "%s\n", cpacket)
		}
	}
	// Start (mitm) attacker server.
	attackerSpawn := func() {
		p := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", p)
		if err != nil {
			fmt.Printf("Attacker listen error: %v\n", err)
			return
		}
		for {
			fmt.Println("Waiting for connection...")
			conn, err := ln.Accept()
			if err != nil {
				fmt.Printf("Attacker accept error: %v", err)
			}
			go attackerHandleConn(conn)
		}
	}

	// Take action based on entity.
	switch {
	case entity == "server":
		serverSpawn()
	case entity == "client":
		clientSpawn()
	case entity == "attacker":
		attackerSpawn()
	default:
		fmt.Println("Error: Uknown entity")
	}
}

// Output:
//
// https://ricketyspace.net/cryptopals/c34.webm
//
//  Part I:
//
// $ ./cryptopals -c 34 server 12000
// Waiting for connection...
// Waiting for connection...
// Made secure connection with 127.0.0.1:6546
// Received from [127.0.0.1:6546]: 'Books are such a drudgery.'
// Closed connection to [127.0.0.1:6546]
//
// $ ./cryptopals -c 34 client 12000
// Made secure connection with 127.0.0.1:12000
// > Books are such a drudgery.
// -> Books are such a drudgery.
// > ^C
//
// Part II:
//
// $ ./cryptopals -c 34 server 12000
// Waiting for connection...
// Made secure connection with 127.0.0.1:46128
// Received from [127.0.0.1:46128]: 'When I have fears that I may cease to be'
// Received from [127.0.0.1:46128]: 'Before my pen has glean'd my teeming brain,'
// Received from [127.0.0.1:46128]: 'Before high piled books, in charactry,'
// Received from [127.0.0.1:46128]: 'Hold like rich garners the full ripen'd grain;'
// Received from [127.0.0.1:46128]: '...'
// Closed connection to [127.0.0.1:46128]
//
// $ ./cryptopals -c 34 attacker 12001 12000
// Waiting for connection...
// Waiting for connection...
// Received from client [127.0.0.1:9186]: 'When I have fears that I may cease to be'
// Received from server [127.0.0.1:12000]: '-> When I have fears that I may cease to be'
// Received from client [127.0.0.1:9186]: 'Before my pen has glean'd my teeming brain,'
// Received from server [127.0.0.1:12000]: '-> Before my pen has glean'd my teeming brain,'
// Received from client [127.0.0.1:9186]: 'Before high piled books, in charactry,'
// Received from server [127.0.0.1:12000]: '-> Before high piled books, in charactry,'
// Received from client [127.0.0.1:9186]: 'Hold like rich garners the full ripen'd grain;'
// Received from server [127.0.0.1:12000]: '-> Hold like rich garners the full ripen'd grain;'
// Received from client [127.0.0.1:9186]: '...'
// Received from server [127.0.0.1:12000]: '-> ...'
// Closed connection to [127.0.0.1:9186]
//
// $ ./cryptopals -c 34 client 12001
// Made secure connection with 127.0.0.1:12001
// > When I have fears that I may cease to be
// -> When I have fears that I may cease to be
// > Before my pen has glean'd my teeming brain,
// -> Before my pen has glean'd my teeming brain,
// > Before high piled books, in charactry,
// -> Before high piled books, in charactry,
// > Hold like rich garners the full ripen'd grain;
// -> Hold like rich garners the full ripen'd grain;
// > ...
// -> ...
// > ^C
