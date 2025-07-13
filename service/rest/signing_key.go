// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"encoding/json"
	"net/http"

	"github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
)

type KeysResponse struct {
	Keys []*dstsprotos.JSONWebKey `json:"keys"`
}

func GetSigningKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, contentTypeJson)
	err := json.NewEncoder(w).Encode(KeysResponse{Keys: sts.GetTokenSigningKey()})
	if err != nil {
		sendInternalServerErrorResponse(w)
		return
	}

	metrics.MetricGetSigningKeyRequests.Inc()
}
