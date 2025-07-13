// package github.com/HPInc/krypton-dsts/service/common
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package common

import "errors"

// toInt32 converts int to int32 in a safe way.
// You get error when the value is out of the 32-bit range.
func ToInt32(i int) (int32, error) {
	if i > 2147483647 || i < -2147483648 {
		return 0, errors.New("int32 out of range")
	}
	return int32(i), nil
}
