all: docker-image

# Build docker dependencies such as the Go builder and base images.
docker-deps:
	make -C base-images build

# Build all the docker images required for the DSTS service. This includes
# the database, cache and the DSTS micro-service itself.
docker-image: docker-deps
	make -C service docker-image

# Run unit tests for the DSTS service in a docker-ized environment.
test:
	make -C tools/compose test

.PHONY: docker-image test
