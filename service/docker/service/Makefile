include ../../common.mk

# Create a docker image for the service and a docker image for running tests.
docker-image:
	docker build -t $(DSTS_DOCKER_IMAGE) --rm -f Dockerfile ../../../
