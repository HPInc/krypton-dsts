// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import "github.com/HPInc/krypton-dsts/service/common"

const (
	authenticationChallengeLength = 10
)

func NewAuthenticationChallenge() string {
	return common.NewRandomString(authenticationChallengeLength)
}
