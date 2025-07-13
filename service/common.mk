GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILT_ON := $(shell hostname)
BUILD_DATE := $(shell date +%FT%T%z)

BINARY_NAME=dstsservice

# Docker images for the DSTS service.
DSTS_DOCKER_IMAGE=krypton-dsts
DSTS_GHCR_IMAGE=ghcr.io/hpinc/krypton/$(DSTS_DOCKER_IMAGE)
TEST_DOCKER_IMAGE=krypton-dsts-test
