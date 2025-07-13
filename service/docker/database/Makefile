DOCKER_IMAGE_NAME=krypton-dsts-db

all: docker-image

docker-image:
	docker build -t $(DOCKER_IMAGE_NAME) --rm \
	-f Dockerfile .

clean:
	docker rmi -f $(DOCKER_IMAGE_NAME)
