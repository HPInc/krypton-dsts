# we assume all test machines have either docker-compose or
# the compose plugin in docker command.
DOCKER_COMPOSE=docker-compose
HAS_DOCKER_COMPOSE := $(shell command -v docker-compose 2> /dev/null)
ifndef HAS_DOCKER_COMPOSE
  DOCKER_COMPOSE=docker compose
  DOCKER_COMPOSE_QUIET_PULL=--quiet-pull
endif

include .env

start:
	$(DOCKER_COMPOSE) -p$(PROJECT) -f docker-compose-deps.yml up \
	$(DOCKER_COMPOSE_QUIET_PULL) -d

test: stop_test start
	$(DOCKER_COMPOSE) -p$(PROJECT) \
		-f docker-compose-test.yml up $(DOCKER_COMPOSE_QUIET_PULL) \
		--exit-code-from $(TEST)

start_dsts:
	$(DOCKER_COMPOSE) -p$(PROJECT) \
		-f docker-compose-deps.yml -f docker-compose-dsts.yml up -d

stop_test:
	-docker rm $(TEST).$(DOMAIN)

stop:
	-$(DOCKER_COMPOSE) -p$(PROJECT) \
		-f docker-compose-deps.yml -f docker-compose-dsts.yml down

show_devices:
	 docker exec $(DB).$(DOMAIN) psql -U $(DB_USER) -d $(DB_NAME) -c "select * from devices order by created_at desc limit 1"

clean: stop
	-docker ps -aqf status=exited | xargs docker rm # remove exited
.PHONY: start stop test start_dsts stop_test show_devices clean
