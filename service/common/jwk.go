// package github.com/HPInc/krypton-dsts/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package common

import (
	"bytes"
	"encoding/binary"
)

type JSONWebKey struct {
	KeyType string      `json:"kty,omitempty"`
	Use     string      `json:"use,omitempty"`
	KeyID   string      `json:"kid,omitempty"`
	Alg     string      `json:"alg,omitempty"`
	X5t     string      `json:"x5t,omitempty"`
	K       *ByteBuffer `json:"k,omitempty"`
	X       *ByteBuffer `json:"x,omitempty"`
	Y       *ByteBuffer `json:"y,omitempty"`
	N       string      `json:"n,omitempty"`
	E       string      `json:"e,omitempty"`
	X5c     []string    `json:"x5c,omitempty"`
}

type ByteBuffer struct {
	Data []byte
}

func newBuffer(data []byte) *ByteBuffer {
	if data == nil {
		return nil
	}
	return &ByteBuffer{
		Data: data,
	}
}

func NewBufferFromInt(num uint64) *ByteBuffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return newBuffer(bytes.TrimLeft(data, "\x00"))
}
