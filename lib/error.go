// Copyright © 2021 rsiddharth <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package lib

// CryptoPals Error
type CPError struct {
	err string
}

func (e CPError) Error() string { return e.err }
