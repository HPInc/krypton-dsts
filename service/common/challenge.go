// package github.com/HPInc/krypton-dsts/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package common

import (
	"math/rand"
	"time"
	"unsafe"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func NewRandomString(length int) string {
	b := make([]byte, length)
	var src = rand.NewSource(time.Now().UnixNano())

	// A src.Int63() generates 63 random bits, enough for letterIdxMax
	// characters!
	for i, cache, remain := length-1, src.Int63(),
		letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	// #nosec G103
	return *(*string)(unsafe.Pointer(&b))
}
