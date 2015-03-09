// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha1 implements the SHA1 hash algorithm as defined in RFC 3174.
package sha1

import (
	"crypto"
	"fmt"
	"hash"
)

func init() {
	crypto.RegisterHash(crypto.SHA1, New)
}

// The size of a SHA1 checksum in bytes.
const Size = 20

// The blocksize of SHA1 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

func (d *digest) setH(h [5]uint32) {
	for i := 0; i < 5; i++ {
		d.h[i] = h[i]
	}
}

// New returns a new hash.Hash computing the SHA1 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}

	fmt.Println("current digest: ", d.h)
	fmt.Println("current len: ", d.len)
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0
	hash := d.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	len := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		fmt.Println("in smaller than branch, writing: ", tmp[0:56-len%64])
		d.Write(tmp[0 : 56-len%64])
	} else {
		fmt.Println("in greater than branch, writing: ", tmp[0:64+56-len%64])
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (56 - 8*i))
	}
	fmt.Println("writing len: ", tmp[0:8])

	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte
	for i, s := range d.h {
		digest[i*4] = byte(s >> 24)
		digest[i*4+1] = byte(s >> 16)
		digest[i*4+2] = byte(s >> 8)
		digest[i*4+3] = byte(s)
	}

	return digest
}

// Sum returns the SHA1 checksum of the data.
func Sum(data []byte) [Size]byte {
	fmt.Println("digesting: ", data)
	var d digest
	d.Reset()
	fmt.Println("current digest: ", d.h)
	fmt.Println("in Sum, about to write: ", data)
	d.Write(data)
	return d.checkSum()
}

// SumWithInitialState returns the SHA1 checksum of the data, but allows the
// caller to set the intial state (h) of the digest.
func SumWithInitialState(data []byte, h [5]uint32) [Size]byte {
	fmt.Println("artisanally digesting: ", data)
	var d digest
	d.Reset()
	fmt.Println("setting initial state of digest to: ", h)
	d.setH(h)
	d.len = 64
	fmt.Println("current digest: ", d.h)
	fmt.Println("in SumWithInitialState, about to write: ", data)
	d.Write(data)
	return d.checkSum()
}
