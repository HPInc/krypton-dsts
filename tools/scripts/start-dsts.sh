#!/bin/bash
NETWORK="krypton-net"
DSTS_CONTAINER_NAME="dsts"
DATABASE_CONTAINER_NAME="dsts-db"
CACHE_CONTAINER_NAME="dsts-cache"
DSTS_IMAGE_NAME="krypton-dsts"
DATABASE_IMAGE_NAME="krypton-dsts-db"
CACHE_IMAGE_NAME="krypton-dsts-cache"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# First check if the required AWS config environment variables are set.
if [[ -z "${AWS_ACCESS_KEY_ID}" ]]; then
    echo -n -e "${RED}Please specify the AWS_ACCESS_KEY_ID environment variable.${NC}"
    echo
    exit 1
fi

if [[ -z "${AWS_SECRET_ACCESS_KEY}" ]]; then
    echo -n -e "${RED}Please specify the AWS_SECRET_ACCESS_KEY environment variable.${NC}"
    echo
    exit 1
fi

if [[ -z "${POSTGRES_PASSWORD}" ]]; then
    echo -n -e "${RED}Please specify the POSTGRES_PASSWORD environment variable.${NC}"
    echo
    exit 1
fi

echo -e "${GREEN}Shutting down existing containers and cleaning up network ...${NC}"
docker rm --force $DSTS_CONTAINER_NAME
docker rm --force $DATABASE_CONTAINER_NAME
docker rm --force $CACHE_CONTAINER_NAME

# Create a docker network for the DSTS service.
echo "Setting up network for DSTS service ..."
docker network inspect $NETWORK >/dev/null 2>&1 || \
    docker network create $NETWORK

# Start up the device database container
docker run -d -p 5432:5432 --net=$NETWORK --name $DATABASE_CONTAINER_NAME \
-e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" $DATABASE_IMAGE_NAME

echo "Waiting for device database container to start up ..."
sleep 10
retval=$(docker inspect -f "{{.State.Running}}" $DATABASE_CONTAINER_NAME)
if [ "${retval[0]}" != true ]; then
    echo -e "${RED}Failed to start the Krypton device database service${NC}";
    exit 1
fi
docker ps --filter name=$DATABASE_CONTAINER_NAME

# Start up the device cache container
docker run -d -p 6379:6379 --net=$NETWORK -e CACHE_PASSWORD="${POSTGRES_PASSWORD}" \
--name $CACHE_CONTAINER_NAME $CACHE_IMAGE_NAME

echo "Waiting for device cache container to start up ..."
sleep 5
retval=$(docker inspect -f "{{.State.Running}}" $CACHE_CONTAINER_NAME)
if [ "${retval[0]}" != true ]; then
    echo -e "${RED}Failed to start the Krypton device cache service${NC}";
    exit 1
fi
docker ps --filter name=$CACHE_CONTAINER_NAME

# Deploy the DSTS service docker container into the network.
echo -e "${GREEN}Starting the Krypton DSTS service ...${NC}"
docker run -d -p 7000:7000 -p 7001:7001 --net $NETWORK \
-e GRPC_GO_LOG_VERBOSITY_LEVEL=99 -e GRPC_TRACE="all" \
-e GO_DEBUG="http2debug=2" -e GRPC_GO_LOG_SEVERITY_LEVEL="info" \
-e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
-e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" -e AWS_REGION="us-west-2" \
-e DSTS_DB_PASSWORD="${POSTGRES_PASSWORD}" -e TEST_MODE="enabled" \
-e DSTS_CACHE_PASSWORD="${POSTGRES_PASSWORD}" \
--name $DSTS_CONTAINER_NAME $DSTS_IMAGE_NAME

echo "Waiting for container to start up ..."
sleep 5
retval=$(docker inspect -f "{{.State.Running}}" $DSTS_CONTAINER_NAME)
if [ "${retval[0]}" != true ]; then
    echo -e "${RED}Failed to start the Krypton DSTS service${NC}";
    exit 1
fi

docker ps --filter name=$DSTS_CONTAINER_NAME

# Determine the IP address of the DSTS container.
DB_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
$DATABASE_CONTAINER_NAME)
CACHE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
$CACHE_CONTAINER_NAME)
DSTS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
$DSTS_CONTAINER_NAME)

echo -e "${GREEN}Krypton DSTS has been deployed into the docker network $NETWORK ${NC}"
echo -e " - Krypton DSTS IP address: $DSTS_IP"
echo -e " - Krypton DSTS DB IP address: $DB_IP"
echo -e " - Krypton DSTS Cache IP address: $CACHE_IP"
