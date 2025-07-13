DOCKER_SUBDIRS= cache database service

all: $(DOCKER_SUBDIRS)

# Build docker images for the DSTS service, its database and its cache.
docker-image: $(DOCKER_SUBDIRS)
$(DOCKER_SUBDIRS):
	$(MAKE) -C $@ docker-image

.PHONY: all $(DOCKER_SUBDIRS)
