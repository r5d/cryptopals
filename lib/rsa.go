// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

import (
	"crypto/rand"
	"math/big"
)

// Represents an RSA key pair.
type RSAPair struct {
	Public  *RSAPub
	Private *RSAPrivate
}

type RSAPub struct {
	e *big.Int
	n *big.Int
}

type RSAPrivate struct {
	d *big.Int
	n *big.Int
}

// Copy b to a.
func biCopy(a, b *big.Int) *big.Int {
	a.SetBytes(b.Bytes())
	if b.Sign() == -1 {
		a.Mul(a, big.NewInt(-1))
	}
	return a
}

func InvMod(a, n *big.Int) (*big.Int, error) {
	// Initialize.
	t0 := big.NewInt(0)
	t1 := big.NewInt(1)
	r0 := biCopy(big.NewInt(0), n)
	r1 := biCopy(big.NewInt(0), a)

	for r1.Cmp(big.NewInt(0)) != 0 {
		q := big.NewInt(0)
		q.Div(r0, r1)

		tt := big.NewInt(0)
		tt = tt.Mul(q, t1)
		tt = tt.Sub(t0, tt)

		biCopy(t0, t1)
		biCopy(t1, tt)

		tr := big.NewInt(0)
		tr = tr.Mul(q, r1)
		tr = tr.Sub(r0, tr)

		biCopy(r0, r1)
		biCopy(r1, tr)
	}

	if r0.Cmp(big.NewInt(1)) > 0 {
		return nil, CPError{"not invertible"}
	}
	if t0.Cmp(big.NewInt(0)) < 0 {
		t0.Add(t0, n)
	}
	return t0, nil
}

func RSAGenKey() (*RSAPair, error) {
	// Initialize.
	e := big.NewInt(3)
	d := big.NewInt(0)
	n := big.NewInt(0)

	// Compute n and d.
	for {
		// Generate prime p.
		p, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			return nil, CPError{"unable to generate p"}
		}

		// Generate prime q.
		q, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			return nil, CPError{"unable to generate q"}
		}

		// Calculate n.
		n = big.NewInt(0).Mul(p, q)

		// Calculate totient.
		p1 := big.NewInt(0).Sub(p, big.NewInt(1)) // p-1
		q1 := big.NewInt(0).Sub(q, big.NewInt(1)) // q-1
		et := big.NewInt(0).Mul(p1, q1)           // Totient `et`.

		// Calculate private key `d`.
		d, err = InvMod(e, et)
		if err != nil {
			continue // Inverse does not does. Try again.
		}
		break
	}
	if n.Cmp(big.NewInt(0)) <= 0 {
		return nil, CPError{"unable to compute n"}
	}
	if d.Cmp(big.NewInt(0)) <= 0 {
		return nil, CPError{"unable to compute d"}
	}

	// Make pub key.
	pub := new(RSAPub)
	pub.e = e
	pub.n = biCopy(big.NewInt(0), n)

	// Make private key.
	prv := new(RSAPrivate)
	prv.d = d
	prv.n = biCopy(big.NewInt(0), n)

	// Make key pair.
	pair := new(RSAPair)
	pair.Public = pub
	pair.Private = prv

	return pair, nil
}

func (r *RSAPub) Encrypt(msg []byte) []byte {
	// Convert message to big int.
	m := big.NewInt(0).SetBytes(msg)

	// Encrypt.
	c := big.NewInt(0).Exp(m, r.e, r.n)

	return c.Bytes()
}

func (r *RSAPub) E() *big.Int {
	return r.e
}

func (r *RSAPub) N() *big.Int {
	return r.n
}

func (r *RSAPrivate) Decrypt(cipher []byte) []byte {
	// Convert cipher to big int.
	c := big.NewInt(0).SetBytes(cipher)

	// Decrypt.
	m := big.NewInt(0).Exp(c, r.d, r.n)

	return m.Bytes()
}
