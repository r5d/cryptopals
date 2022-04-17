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

func (u *SRPUser) EphemeralKeyGen() {
	for {
		u.b = big.NewInt(RandomInt(1, 10000000))
		if u.b.Cmp(big.NewInt(0)) == 1 {
			break
		}
	}
}

func (u *SRPUser) EphemeralKeyPub() (*big.Int, error) {
	if u.k == nil || u.k.Cmp(big.NewInt(0)) != 1 {
		return nil, CPError{"k is not initialized"}
	}
	if u.v == nil || u.v.Cmp(big.NewInt(0)) != 1 {
		return nil, CPError{"v is not initialized"}
	}
	if u.g == nil || u.g.Cmp(big.NewInt(0)) != 1 {
		return nil, CPError{"g is not initialized"}
	}
	if u.b == nil || u.b.Cmp(big.NewInt(0)) != 1 {
		return nil, CPError{"b is not initialized"}
	}

	kv := new(big.Int)
	kv.Mul(u.k, u.v)

	gb := new(big.Int)
	gb.Exp(u.g, u.b, u.n)

	// pub is 'B'
	pub := new(big.Int)
	pub.Add(kv, gb)

	return pub, nil
}

func (u *SRPUser) SetScramblingParam(a *big.Int) error {
	b, err := u.EphemeralKeyPub()
	if err != nil {
		return err
	}
	bb := b.Bytes()
	ab := a.Bytes()

	// Make M=A+B
	m := make([]byte, 0)
	m = append(m, ab...)
	m = append(m, bb...)
	if len(m) != (len(ab) + len(bb)) {
		return CPError{"length of m is incorrect"}
	}

	// Hash M
	u.h.Message(m)
	h := u.h.Hash()

	// Set scrambling paramter u
	u.u = new(big.Int)
	u.u.SetBytes(h)
	if u.u.Cmp(big.NewInt(0)) != 1 {
		return CPError{"u is invalid"}
	}
	return nil
}

func (u *SRPUser) ComputeSessionKey(a *big.Int) error {
	if a.Cmp(big.NewInt(0)) != 1 {
		return CPError{"a is invalid"}
	}

	// v^u
	vu := new(big.Int)
	vu.Exp(u.v, u.u, u.n)

	// S = (A * v^u)  ^ b
	s := new(big.Int)
	s.Mul(a, vu)
	s.Exp(s, u.b, u.n)
	sb := s.Bytes()

	// K = H(S)
	m := make([]byte, 0)
	m = append(m, sb...)
	u.h.Message(m)
	u.sk = u.h.Hash()

	return nil
}

func (u *SRPUser) SessionKeyMacVerify(mac []byte) bool {
	return u.h.MacVerify(u.salt, u.sk, mac)
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

func (s *SRPClientSession) EphemeralKeyPub() (*big.Int, error) {
	if s.g == nil || s.g.Cmp(big.NewInt(0)) != 1 {
		return nil, CPError{"g is not initialized"}
	}
	if s.a == nil || s.a.Cmp(big.NewInt(0)) != 1 {
		return nil, CPError{"a is not initialized"}
	}

	// pub is 'A'
	pub := new(big.Int)
	pub.Exp(s.g, s.a, s.n)

	return pub, nil
}

func (s *SRPClientSession) SetScramblingParam(b *big.Int) error {
	a, err := s.EphemeralKeyPub()
	if err != nil {
		return err
	}
	ab := a.Bytes()
	bb := b.Bytes()

	// Make M=A+B
	m := make([]byte, 0)
	m = append(m, ab...)
	m = append(m, bb...)
	if len(m) != (len(ab) + len(bb)) {
		return CPError{"length of m is incorrect"}
	}

	// Hash M
	s.h.Message(m)
	h := s.h.Hash()

	// Set scrambling paramter u
	s.u = new(big.Int)
	s.u.SetBytes(h)
	if s.u.Cmp(big.NewInt(0)) != 1 {
		return CPError{"u is invalid"}
	}
	return nil
}

func (s *SRPClientSession) ComputeSessionKey(salt []byte,
	pass string, b *big.Int) error {
	if len(salt) < 1 {
		return CPError{"salt invalid"}
	}
	if len(pass) < 1 {
		return CPError{"pass invalid"}
	}

	// salt+pass
	sp := make([]byte, 0)
	copy(sp, salt)
	sp = append(sp, StrToBytes(pass)...)

	// x = H(salt+pass)
	x := new(big.Int)
	s.h.Message(sp)
	x.SetBytes(s.h.Hash())

	// g^x
	gx := new(big.Int)
	gx.Exp(s.g, x, s.n)

	// k * g^x
	kgx := new(big.Int)
	kgx.Mul(s.k, gx)

	// B - (k * g^x)
	bkgx := new(big.Int)
	bkgx.Sub(b, kgx)

	// u * x
	ux := new(big.Int)
	ux.Mul(s.u, x)

	// a + u*x
	aux := new(big.Int)
	aux.Add(s.a, ux)

	// S = (B - (k * g^x)) ^ (a + u*x)
	sec := new(big.Int)
	sec.Exp(bkgx, aux, s.n)
	sb := sec.Bytes()

	// K = H(S)
	m := make([]byte, 0)
	m = append(m, sb...)
	s.h.Message(m)
	s.sk = s.h.Hash()

	return nil
}

func (s *SRPClientSession) SessionKeyMac(salt []byte) ([]byte, error) {
	if len(s.sk) < 1 {
		return nil, CPError{"sk is invalid"}
	}
	if len(salt) < 1 {
		return nil, CPError{"salt is invalid"}
	}
	return s.h.Mac(salt, s.sk), nil
}
