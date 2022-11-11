// Copyright © 2022 siddharth ravikumar <s@ricketyspace.net>
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

func C37(args []string) {
	usage := func() {
		fmt.Println("Usage: cryptopals -c 37 [ client | server ] PORT [ PUBKEY ]")
		fmt.Println("\n       PUBKEY is required for the client. Valid values are")
		fmt.Println("       0, N1, N2, N3, N4, etc.")
	}
	if len(args) < 2 {
		usage()
		return
	}
	entity := args[0]
	port, err := lib.StrToNum(args[1])
	if err != nil {
		fmt.Println("port invalid")
		return
	}
	if port < 12000 {
		fmt.Println("port number must be >= 12000")
		return
	}

	// SRP params.
	paramN := lib.StripSpaceChars(
		`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                 e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                 c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                 bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                 fffffffffffff`)
	paramG := "2"
	paramK := "3"

	// Process client's pub key if this is a client.
	clientPubKey := []byte{}
	if entity == "client" {
		if len(args) != 3 {
			usage()
			return
		}
		pub := args[2]
		// Validate pub key.
		switch {
		case pub[0] == '0':
			clientPubKey = []byte{0}
		case len(pub) > 1 && pub[0] == 'N':
			pow, err := lib.StrToNum(pub[1:])
			if err != nil {
				fmt.Printf("error: public key invalid\n")
				return
			}
			pubi, ok := new(big.Int).SetString(
				lib.StripSpaceChars(paramN),
				16,
			)
			if !ok {
				fmt.Printf("unable to process pub key")
				return
			}
			if pow == 1 {
				clientPubKey = pubi.Bytes()
				pubi = pubi.Exp(pubi, big.NewInt(int64(pow)), pubi)
			} else {
				pubi = pubi.Exp(pubi, big.NewInt(int64(pow)), pubi)
				if pubi.Cmp(big.NewInt(0)) == 0 {
					clientPubKey = []byte{0}
				} else {
					clientPubKey = pubi.Bytes()
				}
			}
		default:
			usage()
			return
		}
	}

	// Zero key.
	zeroSessionKey := func() []byte {
		// SHA256 of empty string.
		sha256 := lib.Sha256{}
		sha256.Init([]uint32{})
		sha256.Message([]byte{})
		return sha256.Hash()
	}
	// Register user on the server.
	serverRegisterUser := func(server *lib.SRPServer, info []string) error {
		if len(info) != 5 {
			return fmt.Errorf("regiser user: info valid")
		}
		n := info[0]
		g := info[1]
		k := info[2]
		ident := info[3]
		pass := info[4]
		user, err := lib.NewSRPUser(n, g, k, ident, pass)
		if err != nil {
			return fmt.Errorf("register user: %v", err)
		}
		if err = server.RegisterUser(user); err != nil {
			return fmt.Errorf("register user: %v", err)
		}
		return nil
	}
	// Login user on the server.
	serverLoginUser := func(server *lib.SRPServer, info []string,
		conn net.Conn) error {
		if len(info) != 2 {
			return fmt.Errorf("login user: info invalid")
		}
		ident := info[0]
		user, err := server.GetUser(ident)
		if err != nil {
			return fmt.Errorf("get user: %v", err)
		}
		if user.LoggedIn() {
			return fmt.Errorf("user already has a session open")
		}
		clientPub := new(big.Int).SetBytes(lib.HexStrToBytes(info[1]))

		user.EphemeralKeyGen() // Generate server pub key for user.
		serverPub, err := user.EphemeralKeyPub()
		if err != nil {
			return fmt.Errorf("server pub key: %v", err)
		}

		// Make ACK packet
		packet := fmt.Sprintf("%s+%s", lib.BytesToHexStr(user.Salt()),
			lib.BytesToHexStr(serverPub.Bytes()))

		// Send packet to client.
		_, err = fmt.Fprintf(conn, "%s\n", packet)
		if err != nil {
			return fmt.Errorf("sending packet to client: %v", err)
		}

		// Compute session key.
		err = user.SetScramblingParam(clientPub)
		if err != nil {
			return fmt.Errorf("setting scrambling param: %v", err)
		}
		err = user.ComputeSessionKey(clientPub)
		if err != nil {
			return fmt.Errorf("computing session key: %v", err)
		}

		// Wait and try to read hmac from client.
		cpacket, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return fmt.Errorf("hmac recv: %v", err)
		}
		hmac := []byte(cpacket[:len(cpacket)-1])
		if !user.SessionKeyMacVerify(hmac) {
			return fmt.Errorf("hmac verification failed")
		}
		// Login user.
		user.LogIn()

		return nil
	}
	// Logout user on the server.
	serverLogoutUser := func(server *lib.SRPServer, ident string,
		conn net.Conn) error {
		user, err := server.GetUser(ident)
		if err != nil {
			return fmt.Errorf("get user: %v", err)
		}
		if !user.LoggedIn() {
			return fmt.Errorf("user not logged in")
		}
		// Logout user.
		user.LogOut()
		return nil
	}
	// Handle connection from a client.
	serverHandleConn := func(server *lib.SRPServer, conn net.Conn) {
		defer conn.Close()
		fmt.Printf("Got connection from %v\n", conn.RemoteAddr())

		// Read packet from client.
		packet, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Printf("Unable to read from client %v\n",
				conn.RemoteAddr())
			return
		}

		// Remove newline character from packet.
		packet = packet[:len(packet)-1]

		parts := lib.StrSplitAt('+', packet)
		if len(parts) < 2 {
			fmt.Fprintf(conn, "invalid request\n")
			return
		}

		switch {
		case parts[0] == "register":
			err = serverRegisterUser(server, parts[1:])
			if err != nil {
				fmt.Fprintf(conn, "%v\n", err)
				return
			} else {
				fmt.Fprintf(conn, "OK\n")
			}
			return
		case parts[0] == "login":
			err = serverLoginUser(server, parts[1:], conn)
			if err != nil {
				fmt.Fprintf(conn, "%v\n", err)
			} else {
				fmt.Fprintf(conn, "OK\n")
			}
			return
		case parts[0] == "logout":
			err = serverLogoutUser(server, parts[1], conn)
			if err != nil {
				fmt.Fprintf(conn, "%v\n", err)
			} else {
				fmt.Fprintf(conn, "OK\n")
			}
			return
		default:
			fmt.Fprintf(conn, "invalid action")
			return
		}

	}
	// Start SRP server.
	serverSpawn := func() {
		server := new(lib.SRPServer)

		p := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", p)
		if err != nil {
			fmt.Printf("server listen error: %v\n", err)
			return
		}
		for {
			fmt.Println("Waiting for connection...")
			conn, err := ln.Accept()
			if err != nil {
				fmt.Printf("server accept error: %v\n", err)
			}
			go serverHandleConn(server, conn)
		}
	}
	// Register user with server.
	clientRegisterUser := func(client *lib.SRPClient, ident string) error {
		n := paramN
		g := paramG
		k := paramK

		// Prompt for password.
		fmt.Printf("password> ")
		pass, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("unable to read password: %v", err)
		}

		// Create session for user.
		client.Session, err = lib.NewSRPClientSession(n, g, k, ident)
		if err != nil {
			return fmt.Errorf("unable to create session: %v", err)
		}

		// Make SRP registration packet.
		packet := fmt.Sprintf("%s+%s+%s+%s+%s+%s", "register",
			n, g, k, ident, pass)

		// Try to connect to server.
		conn, err := net.Dial("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("unable connect to server: %v", err)
		}
		defer conn.Close()

		// Send packet to server.
		_, err = fmt.Fprintf(conn, "%s", packet)
		if err != nil {
			return fmt.Errorf("unable communicate with server: %v", err)
		}

		// Wait and try to get registration ACK from server.
		spacket, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return fmt.Errorf("server did not respond: %v", err)
		}
		// Remove newline character.
		spacket = spacket[:len(spacket)-1]
		if spacket != "OK" {
			return fmt.Errorf("server registration failed: %s", spacket)
		}
		return nil
	}
	// Login user into the server.
	clientLoginUser := func(client *lib.SRPClient, ident string) error {
		n := paramN
		g := paramG
		k := paramK

		// Prompt for password.
		fmt.Printf("password> ")
		pass, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("unable to read password: %v", err)
		}
		pass = pass[:len(pass)-1]

		// Create session for user.
		client.Session, err = lib.NewSRPClientSession(n, g, k, ident)
		if err != nil {
			return fmt.Errorf("unable to create session: %v", err)
		}

		// Set public key to N^t where t is 0, 1, 2, etc.
		pub := clientPubKey

		// Make SRP login packet.
		packet := fmt.Sprintf("%s+%s+%s", "login",
			ident, lib.BytesToHexStr(pub))

		// Try to connect to server.
		conn, err := net.Dial("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("unable connect to server: %v", err)
		}
		defer conn.Close()

		// Send login packet to server.
		_, err = fmt.Fprintf(conn, "%s\n", packet)
		if err != nil {
			return fmt.Errorf("unable communicate with server: %v", err)
		}

		// Wait and try to get registration ACK from server.
		spacket, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return fmt.Errorf("server did not respond: %v", err)
		}
		// Remove newline character.
		spacket = spacket[:len(spacket)-1]

		if !lib.StrHas(spacket, "+") {
			return fmt.Errorf("pub exchange: %s", spacket)
		}
		parts := lib.StrSplitAt('+', spacket)
		if len(parts) < 2 {
			return fmt.Errorf("server login response invalid")
		}
		salt := lib.HexStrToBytes(parts[0])
		serverPub := new(big.Int).SetBytes(lib.HexStrToBytes(parts[1]))

		// Compute session key.
		err = client.Session.SetScramblingParam(serverPub)
		if err != nil {
			return fmt.Errorf("setting scrambling param: %v", err)
		}
		err = client.Session.ComputeSessionKey(salt, pass, serverPub)
		if err != nil {
			return fmt.Errorf("computing session key: %v", err)
		}

		// Set to "zero" session key. Since the client's
		// public key is a multiple of N, the session key will
		// always be zero.
		client.Session.SetSessionKey(zeroSessionKey())

		// Compute session key hmac
		hmac, err := client.Session.SessionKeyMac(salt)
		if err != nil {
			return fmt.Errorf("session key hmac: %v", err)
		}

		// Send hmac to server.
		_, err = fmt.Fprintf(conn, "%s\n", hmac)
		if err != nil {
			return fmt.Errorf("sending hmac: %v", err)
		}

		// Wait and try to get registration ACK from server.
		spacket, err = bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return fmt.Errorf("server did not respond: %v", err)
		}
		// Remove newline character.
		spacket = spacket[:len(spacket)-1]
		if spacket != "OK" {
			return fmt.Errorf("login failed: %s", spacket)
		}
		// Login user.
		client.LogIn()
		return nil
	}
	// Logout user.
	clientLogoutUser := func(client *lib.SRPClient) error {
		// Make logout packet.
		packet := fmt.Sprintf("%s+%s", "logout", client.Ident())

		// Try to connect to server.
		conn, err := net.Dial("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("unable connect to server: %v", err)
		}
		defer conn.Close()

		// Send login packet to server.
		_, err = fmt.Fprintf(conn, "%s\n", packet)
		if err != nil {
			return fmt.Errorf("logout send: %v", err)
		}

		// Wait and try to get logout ACK from server.
		spacket, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return fmt.Errorf("logout recv: %v", err)
		}
		// Remove newline character.
		spacket = spacket[:len(spacket)-1]
		if spacket != "OK" {
			return fmt.Errorf("logout ack: %s", spacket)
		}

		// Logout user.
		client.Session = nil

		return nil
	}
	// Start SRP client.
	clientSpawn := func() {
		client := new(lib.SRPClient)
		// Enter repl.
		for {
			// Read message from stdin.
			fmt.Printf("%s> ", client.Ident())
			msg, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				fmt.Printf("read error: %v\n", err)
				return
			}
			// Remove newline character.
			msg = msg[:len(msg)-1]

			msg_parts := lib.StrSplitAt(' ', msg)
			switch {
			case !client.LoggedIn() && msg_parts[0] == "register" &&
				len(msg_parts) == 2:
				err := clientRegisterUser(client, msg_parts[1])
				if err != nil {
					fmt.Printf("Registration failed: %v\n", err)
				} else {
					fmt.Printf("Registered!\n")
				}
			case !client.LoggedIn() && msg_parts[0] == "login" &&
				len(msg_parts) == 2:
				err := clientLoginUser(client, msg_parts[1])
				if err != nil {
					fmt.Printf("Login failed: %v\n", err)
				} else {
					fmt.Printf("Logged in!\n")
				}
			case client.LoggedIn() && msg_parts[0] == "logout":
				err := clientLogoutUser(client)
				if err != nil {
					fmt.Printf("Logout failed: %v\n", err)
				} else {
					fmt.Printf("Logged out!\n")
				}
			}
		}
	}

	// Take action based on entity.
	switch {
	case entity == "server":
		serverSpawn()
	case entity == "client":
		clientSpawn()
	default:
		fmt.Println("uknown entity")
	}
}

// Output:
//
// https://ricketyspace.net/cryptopals/c37.webm
//
// $ ./cryptopals -c 37 server 12000
// Waiting for connection...
// Waiting for connection...
// Got connection from 127.0.0.1:25923
// Waiting for connection...
// Got connection from 127.0.0.1:47437
// Waiting for connection...
// Got connection from 127.0.0.1:47489
// Waiting for connection...
// Got connection from 127.0.0.1:17179
// Waiting for connection...
// Got connection from 127.0.0.1:24965
// Waiting for connection...
// Got connection from 127.0.0.1:26381
// Waiting for connection...
// Got connection from 127.0.0.1:4572
// Waiting for connection...
// Got connection from 127.0.0.1:47202
// Waiting for connection...
// Got connection from 127.0.0.1:42154
//
// $ ./cryptopals -c 37 client 12000 0
// > register bob
// password> theonjoy
// Registered!
// > login bob
// password>
// Logged in!
// bob> logout
// Logged out!
// > ^C
// ada$ ./cryptopals -c 37 client 12000 N1
// > login bob
// password>
// Logged in!
// bob> logout
// Logged out!
// > ^C
// ada$ ./cryptopals -c 37 client 12000 N2
// > login bob
// password>
// Logged in!
// bob> logout
// Logged out!
// > ^C
// ada$ ./cryptopals -c 37 client 12000 N9
// > login bob
// password>
// Logged in!
// bob> logout
// Logged out!
// > ^C
