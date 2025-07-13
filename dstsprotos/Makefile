DSTS_PROTOS_DOCKER_IMAGE=krypton-dstsprotos
DSTS_GHCR_IMAGE=ghcr.io/hpinc/krypton/$(DSTS_PROTOS_DOCKER_IMAGE)

PROTOS_DIR=.
PROTOC_PATH=/usr/local/bin
PROTOC_CMD=protoc
PROTOC_BUILD=$(PROTOC_PATH)/$(PROTOC_CMD)

all: docker-image

build-proto:
	$(PROTOC_BUILD) -I . -I $(PROTOS_DIR) \
	--go_out=paths=source_relative:$(PROTOS_DIR) \
	--go-grpc_out=paths=source_relative:$(PROTOS_DIR) \
	$(PROTOS_DIR)/dsts.proto $(PROTOS_DIR)/common.proto \
	$(PROTOS_DIR)/device.proto $(PROTOS_DIR)/signing_key.proto \
	$(PROTOS_DIR)/enrollment_token.proto $(PROTOS_DIR)/app_auth.proto

docker-image:
	docker build -t $(DSTS_PROTOS_DOCKER_IMAGE) -f Dockerfile .

tag:
	docker tag $(DSTS_PROTOS_DOCKER_IMAGE):latest $(DSTS_GHCR_IMAGE):latest

publish: docker-image tag
	docker push $(DSTS_GHCR_IMAGE):latest

clean:
	docker rmi -f $(DSTS_PROTOS_DOCKER_IMAGE)
