BINARY_DIR=../bin/dsts
cwd=$(shell pwd)

include common.mk

all: build docker-image
build: build-binaries

gosec:
	gosec ./...

# Generate golang files from the protobuf definitions.
build-proto:
	make -C ../dstsprotos build-proto

# Build the binaries for the service.
build-binaries: build-proto
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) \
	-ldflags "-X main.gitCommitHash=$(GIT_COMMIT) -X main.builtAt=$(BUILD_DATE) \
	-X main.builtBy=$(USER) -X main.builtOn=$(BUILT_ON)" \
	-o $(BINARY_DIR)/$(BINARY_NAME) -v
	cp -r config $(BINARY_DIR)/
	cp -r db/schema $(BINARY_DIR)/

# Resolve dependencies for the test.
testdeps:
	$(GOGET) google.golang.org/grpc/test/bufconn

# Build test binaries for the service.
build-test-binaries: build-proto testdeps
	make -C rpc build-test-binaries

# Create docker images for the service & its dependencies.
docker-image:
	make -C docker docker-image

# Start the Device STS and its dependencies within a local Docker network.
start:
	bash ../tools/scripts/start-dsts.sh

test:
	make -C ../tools/compose test

# Run unit tests for the Device STS in a docker-ized environment.
service-unit-tests:
	DSTS_CONFIG_LOCATION=$(cwd)/config/config.yaml \
	DSTS_REGISTERED_APP_CONFIG_FILE=$(cwd)/config/registered_apps.yaml \
	DSTS_DB_SCHEMA_LOCATION=$(cwd)/db/schema go test ./...

# Publish the Device STS docker image to Github.
publish:
	docker tag $(DSTS_DOCKER_IMAGE):latest $(DSTS_GHCR_IMAGE):latest
	docker push $(DSTS_GHCR_IMAGE):latest

clean:
	-docker ps -aqf status=exited | xargs docker rm # remove exited
	@docker rmi -f $(DSTS_DOCKER_IMAGE)
	$(GOCLEAN)
	@rm -rf $(BINARY_DIR)
	
.PHONY: docker-image build-proto build-binaries testdeps build-test-binaries test start publish clean
