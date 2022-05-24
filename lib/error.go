// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// CryptoPals Error
type CPError struct {
	Err string
}

func (e CPError) Error() string { return e.Err }
