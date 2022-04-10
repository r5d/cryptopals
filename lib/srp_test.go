// Copyright © 2022 siddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"math/big"
	"testing"
)

func TestNewSRPUser(t *testing.T) {
	n := StripSpaceChars(
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
	ident := "s@ricketyspace.net"
	pass := "d59d6c93af0f37f272d924979"
	user, err := NewSRPUser(n, g, k, ident, pass)
	if err != nil {
		t.Errorf("Error: %v\n", err)
		return
	}

	// Check n.
	bigN, _ := new(big.Int).SetString(StripSpaceChars(n), 16)
	if user.n.Cmp(bigN) != 0 {
		t.Error("Error: n not set correctly\n")
		return
	}
	// Check g.
	bigG, _ := new(big.Int).SetString(StripSpaceChars(g), 16)
	if user.g.Cmp(bigG) != 0 {
		t.Error("Error: g not set correctly\n")
		return
	}
	// Check k.
	bigK, _ := new(big.Int).SetString(StripSpaceChars(k), 16)
	if user.k.Cmp(bigK) != 0 {
		t.Error("Error: k not set correctly\n")
		return
	}
	// Check ident.
	if user.ident != ident {
		t.Error("Error: user not set correctly\n")
		return
	}
	// Check salt.
	if len(user.salt) < 8 {
		t.Error("Error: salt not set correctly\n")
		return
	}
	// Check x.
	if user.x.Cmp(big.NewInt(1)) < 0 {
		t.Error("Error: x not set correctly\n")
		return
	}
	// Check v.
	if user.v.Cmp(big.NewInt(1)) < 0 {
		t.Error("Error: v not set correctly\n")
		return
	}
}

func TestNewSRPClientSession(t *testing.T) {
	n := StripSpaceChars(
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
	ident := "s@ricketyspace.net"
	session, err := NewSRPClientSession(n, g, k, ident)
	if err != nil {
		t.Errorf("Error: %v\n", err)
		return
	}

	// Check n.
	bigN, _ := new(big.Int).SetString(StripSpaceChars(n), 16)
	if session.n.Cmp(bigN) != 0 {
		t.Error("Error: n not set correctly\n")
		return
	}
	// Check g.
	bigG, _ := new(big.Int).SetString(StripSpaceChars(g), 16)
	if session.g.Cmp(bigG) != 0 {
		t.Error("Error: g not set correctly\n")
		return
	}
	// Check k.
	bigK, _ := new(big.Int).SetString(StripSpaceChars(k), 16)
	if session.k.Cmp(bigK) != 0 {
		t.Error("Error: k not set correctly\n")
		return
	}
	// Check ident.
	if session.ident != ident {
		t.Error("Error: user not set correctly\n")
		return
	}
	// Check a.
	if session.a.Cmp(big.NewInt(1)) < 0 {
		t.Error("Error: a not set correctly\n")
		return
	}
}
