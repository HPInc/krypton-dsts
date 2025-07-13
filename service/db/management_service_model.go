// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"strings"

	"go.uber.org/zap"
)

type ManagementService struct {
	// The ID of the device management service.
	ServiceId string `json:"service_id"`

	// The name of the management service.
	Name string `json:"service_name"`

	// Whether the device management service is considered the default.
	IsDefault bool `json:"-"`
}

var (
	managementServiceList      map[string]ManagementService
	defaultManagementServiceID string
)

// Get the list of management services registered with the device STS.
func getRegisteredManagementServices() error {

	// Retrieve the list of device management services configured in the
	// device database.
	services := []ManagementService{}
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()

	response, err := gDbPool.Query(ctx, queryGetManagementServices)
	if err != nil {
		dstsLogger.Error("Failed to get a list of management services from the database!",
			zap.Error(err),
		)
		return err
	}
	defer response.Close()

	for response.Next() {
		var s ManagementService
		err = response.Scan(&s.ServiceId, &s.Name, &s.IsDefault)
		if err != nil {
			dstsLogger.Error("Failed to get a list of management services from the database!",
				zap.Error(err),
			)
			return err
		}
		services = append(services, s)
	}

	if response.Err() != nil {
		dstsLogger.Error("Failed reading list of services from the database!",
			zap.Error(response.Err()),
		)
		return response.Err()
	}

	// Create a lookaside list of management services to be used for lookup purposes.
	managementServiceList = make(map[string]ManagementService, len(services))
	for _, item := range services {
		managementServiceList[strings.ToLower(item.ServiceId)] = item

		// Set the default management service, if not already set.
		if defaultManagementServiceID == "" {
			if item.IsDefault {
				defaultManagementServiceID = item.ServiceId
			}
		}
	}

	return nil
}

// Find information about the specified management service.
func lookupManagementService(serviceID string) (*ManagementService, error) {
	if serviceID == "" {
		serviceID = defaultManagementServiceID
	}

	item, ok := managementServiceList[strings.ToLower(serviceID)]
	if !ok {
		dstsLogger.Error("Specified management service was not found in the list of registered services!",
			zap.String("Specified management service:", serviceID),
		)
		return nil, ErrNotFound
	}
	return &item, nil
}
