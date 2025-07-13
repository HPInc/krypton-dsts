DOCKER_IMAGE_NAME=krypton-cache

ifndef DOCKER_FILE
  DOCKER_FILE=Dockerfile
endif

ifndef TARGET_REPO
  TARGET_REPO=ghcr.io/hpinc/krypton
endif

build: docker-image
docker-image:
	docker --debug build -t $(DOCKER_IMAGE_NAME) -f $(DOCKER_FILE) .

LOCAL_TEST=dsts_cache

test: ping_test stop

ping_test:
	docker run \
		--name $(LOCAL_TEST) \
		--rm -d \
		-e CACHE_PASSWORD=dstscache \
		-e REDISCLI_AUTH=dstscache \
		$(DOCKER_IMAGE_NAME)
	docker exec $(LOCAL_TEST) redis-cli ping

publish: push

tag:
	docker tag $(DOCKER_IMAGE_NAME) $(TARGET_REPO)/$(DOCKER_IMAGE_NAME)

push: tag
	docker push $(TARGET_REPO)/$(DOCKER_IMAGE_NAME)

stop:
	docker stop $(LOCAL_TEST)

clean: clean-base stop

.SILENT:
.PHONY: all docker-image test clean pull tag push publish
