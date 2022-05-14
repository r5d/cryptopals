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

func C36(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: cryptopals -c 36 [ client | server ] PORT")
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
			return fmt.Errorf("login user: info valid")
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
		if clientPub.Cmp(big.NewInt(0)) == 0 {
			return fmt.Errorf("user public key invalid")
		}

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
		n := lib.StripSpaceChars(
			`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                         e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                         3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                         6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                         24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                         c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                         bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                         fffffffffffff`)
		g := "2"
		k := "3"

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
		n := lib.StripSpaceChars(
			`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                         e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                         3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                         6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                         24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                         c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                         bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                         fffffffffffff`)
		g := "2"
		k := "3"

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

		// Get session pub key.
		pub, err := client.Session.EphemeralKeyPub()
		if err != nil {
			return fmt.Errorf("unable to get pub key: %v", err)
		}

		// Make SRP login packet.
		packet := fmt.Sprintf("%s+%s+%s", "login",
			ident, lib.BytesToHexStr(pub.Bytes()))

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

		// Compute session key hmac
		hmac, err := client.Session.SessionKeyMac(salt)
		if err != nil {
			return fmt.Errorf("sesion key hmac: %v", err)
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
