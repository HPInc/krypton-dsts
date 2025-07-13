# The Krypton Device Security Token Service (DSTS)
The Krypton Device Security Token Service (STS) also referred to as the Krypton DSTS is a micro-service written in Go. It is used to perform device authentication of devices registered for management with the Krypton system. Once devices are authenticated, a device access token is issued. This access token is signed by the DSTS and identifies the device by asserting its unique device identifier as a claim in the token.

The DSTS has the following network interfaces:
 - A REST (HTTP) endpoint - used primary for health checks, collecting metrics and for device authentication.
 - A gRPC endpoint - used for many device lifecycle management operations such as creating, modifying and deleting devices, signing keys and enrollment tokens. For a list of the operations exposed by the gRPC endpoint, view the dsts.proto file within the ```dsprotos``` folder.


## Base images
There is a folder called ```base-images``` at the root of the repository. This folder includes dockerfiles for all base images required for the DSTS service including:
1. ```krypton-go-builder``` - An Alpine Linux based docker image that can be used to build the Krypton Go micro-services. It includes a working Go environment and the protoc compiler and other dependencies required for building and running unit tests for the service.
2. ```krypton-go-base``` - A minimal Alpine Linux docker image that is used to run the Krypton services.
3. ```postgres``` - A docker image for the PostgreSQL server that is used as a database for various Krypton services including the DSTS. This is provided for local development and testing purposes. You can use a managed database service in the cloud or spin up a PostgreSQL instance on a VM in production environments.
4. ```redis``` - A docker image for Redis server which is used by various Krypton services for caching purposes. This is provided for local development and testing purposes. You can use a managed caching service in the cloud or spin up a Redis instance on a VM in production environments.

**NOTE:** These docker images are published to the GHCR (Github Container Registry) docker repository so they can be used by other Krypton service Github repositories.


## Build instructions
Builds use docker to create an isolated and repeatable build environment. You need to have docker and make installed on your Linux machine.

To build, type the following commands at the root of the repository:

1. Build the docker images required for building the Krypton DSTS.
```
make docker-deps
```

2. Build the DSTS service docker image
```
make docker-image
```

Alternately you can type ```make all``` to perform both steps at once.


## Execute unit-tests
Unit testing also uses a docker environment. To run unit tests, type the following command at the root of the repository:

```
make test
```
