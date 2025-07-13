// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"go.uber.org/zap"
)

func checkResponseCode(t *testing.T, expected, actual int) {
	if expected != actual {
		dstsLogger.Error("Mismatch in expected response code",
			zap.Any("Expected", expected),
			zap.Any("Received", actual),
		)
		t.Errorf("*** Test case failed due to mismatched return code! ***")
		return
	}
	t.Logf("Received response code %d as expected!\n", expected)
}

func printJSONResponse(t *testing.T, jsonResponse *bytes.Buffer) {
	body, err := io.ReadAll(jsonResponse)
	if err != nil {
		t.Errorf("Failed to read JSON response. Error: %v\n", err)
		return
	}

	var out bytes.Buffer
	err = json.Indent(&out, body, "", "  ")
	if err != nil {
		t.Errorf("Failed to indent JSON response! Error: %v\n", err)
		return
	}
	dstsLogger.Info("Response from server",
		zap.String("JSON response:", out.String()))
}

func parseJSONResponse(t *testing.T,
	jsonResponse *bytes.Buffer, out interface{}) error {
	body, err := io.ReadAll(jsonResponse)
	if err != nil {
		t.Errorf("Failed to read JSON response. Error: %v\n", err)
		return err
	}

	err = json.Unmarshal(body, &out)
	if err != nil {
		t.Errorf("Failed to indent JSON response! Error: %v\n", err)
		return err
	}

	return nil
}
