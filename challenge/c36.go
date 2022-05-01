// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"ricketyspace.net/cryptopals/lib"
)

// Usage:
//
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
	// Start SRP client.
	clientSpawn := func() {
		client := new(lib.SRPClient)
		// Enter repl.
		for {
			// Read message from stdin.
			fmt.Printf("> ")
			msg, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				fmt.Printf("read error: %v\n", err)
				return
			}
			// Remove newline character.
			msg = msg[:len(msg)-1]

			msg_parts := lib.StrSplitAt(' ', msg)
			switch {
			case msg_parts[0] == "register" && len(msg_parts) == 2:
				err := clientRegisterUser(client, msg_parts[1])
				if err != nil {
					fmt.Printf("Registration failed: %v\n", err)
				} else {
					fmt.Printf("Registered!\n")
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
