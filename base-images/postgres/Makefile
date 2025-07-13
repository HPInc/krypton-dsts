DOCKER_IMAGE_NAME=krypton-db

ifndef DOCKER_FILE
  DOCKER_FILE=Dockerfile
endif

ifndef TARGET_REPO
  TARGET_REPO=ghcr.io/hpinc/krypton
endif

build: docker-image
docker-image:
	docker --debug build -t $(DOCKER_IMAGE_NAME) -f $(DOCKER_FILE) .

test:

publish: push

tag:
	docker tag $(DOCKER_IMAGE_NAME) $(TARGET_REPO)/$(DOCKER_IMAGE_NAME)

push: tag
	docker push $(TARGET_REPO)/$(DOCKER_IMAGE_NAME)

clean: clean-base

.SILENT:
.PHONY: build docker-image test clean tag push publish
