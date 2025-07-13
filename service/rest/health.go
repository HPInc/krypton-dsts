// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"net/http"
)

func GetHealthHandler(w http.ResponseWriter, r *http.Request) {
	_ = sendJsonResponse(w, http.StatusOK, nil)
}
