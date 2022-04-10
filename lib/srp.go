// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import "math/big"

// SRP - implementation.
// Reference http://srp.stanford.edu/design.html

// SRP Client UI - Spec
//
// > register s@ricketyspace.net
// Enter password
// > ******
// Registering with server...registered!
// > login s@ricketyspace.net
// Enter password
// > ******
// Logging in...in!
// s@ricketyspace.net>
// s@ricketyspace.net> login s@ricketyspace.net
// login command not allowed when logged in
// s@ricketyspace.net> register rsd@gnu.org
// register command not allowed when logged in
// s@ricketyspace.net> logout
// Logging out..out!
// > register s@ricketyspace.net
// Already registered!

// SRP Server.
type SRPServer struct {
	users []SRPUser
}

// Registered user on the SRP server.
type SRPUser struct {
	// Large safe prime. Server and client agree upon the value of
	// N.
	n *big.Int
	// Generator modulo N. Server and client agree upon the value
	// of N.
	g *big.Int
	// Multipier parameter. Server and client agree upon the value
	// of N.
	k *big.Int
	// Hashing object for H() function.
	h Sha256
	// User's email address
	ident string
	// Salt. Randomly generator by the server.
	salt []byte
	// Private key derived from salt and user's pass.
	x *big.Int
	// Scrambling parameter.
	u *big.Int
	// Secret ephemeral value.
	b *big.Int
	// Password verifier.
	v *big.Int
	// Session key.
	sk []byte
}

// SRP client.
type SRPClient struct {
	session SRPClientSession
}

// User session on the SRP client.
type SRPClientSession struct {
	// Large safe prime. Client and server agree upon the value of
	// N.
	n *big.Int
	// Generator modulo N. Client and server agree upon the value
	// of N.
	g *big.Int
	// Multipier parameter. Client and server agree upon the value
	// of N.
	k *big.Int
	// Hashing object for H() function.
	h Sha256
	// User's email address
	ident string
	// Scrambling parameter.
	u *big.Int
	// Secret ephemeral value.
	a *big.Int
	// Session key.
	sk []byte
}

func NewSRPUser(n, g, k, ident, pass string) (*SRPUser, error) {
	var err error
	var ok bool

	user := new(SRPUser)
	user.n, ok = new(big.Int).SetString(StripSpaceChars(n), 16)
	if !ok {
		return nil, CPError{"n is invalid"}
	}
	user.g, ok = new(big.Int).SetString(StripSpaceChars(g), 16)
	if !ok {
		return nil, CPError{"g is invalid"}
	}
	user.k, ok = new(big.Int).SetString(StripSpaceChars(k), 16)
	if !ok {
		return nil, CPError{"k is invalid"}
	}
	user.ident = ident
	user.x = big.NewInt(0)
	user.v = big.NewInt(0)

	// Initialize hashing object.
	user.h = Sha256{}
	user.h.Init([]uint32{})

	// Generate salt.
	user.salt, err = RandomBytes(8)
	if err != nil {
		return nil, err
	}

	// Generate private key `x` from salt+pass
	m := make([]byte, 0)
	copy(m, user.salt)
	m = append(m, StrToBytes(pass)...)
	user.h.Message(m)
	user.x.SetBytes(user.h.Hash())

	// Generate password verifier `v`
	user.v.Exp(user.g, user.x, user.n)

	return user, nil
}

func NewSRPClientSession(n, g, k, ident string) (*SRPClientSession, error) {
	var ok bool

	session := new(SRPClientSession)
	session.n, ok = new(big.Int).SetString(StripSpaceChars(n), 16)
	if !ok {
		return nil, CPError{"n is invalid"}
	}
	session.g, ok = new(big.Int).SetString(StripSpaceChars(g), 16)
	if !ok {
		return nil, CPError{"g is invalid"}
	}
	session.k, ok = new(big.Int).SetString(StripSpaceChars(k), 16)
	if !ok {
		return nil, CPError{"k is invalid"}
	}
	session.ident = ident

	// Initialize hashing object.
	session.h = Sha256{}
	session.h.Init([]uint32{})

	// Generate secret ephemeral value.
	session.a = big.NewInt(RandomInt(1, 10000000))

	return session, nil
}
