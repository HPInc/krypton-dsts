all: docker-image

# Docker dependencies required such as the Go builder and base images 
# will be downloaded from the Krypton utilities docker repository.

# Build all the docker images required for the DSTS service. This includes
# the database, cache and the DSTS micro-service itself.
docker-image:
	make -C service docker-image
	
clean:
	make -C service clean

# Run unit tests for the DSTS service in a docker-ized environment.
test:
	make -C tools/compose test

.PHONY: docker-image test
