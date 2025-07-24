# The Krypton Device Security Token Service (DSTS)
The Krypton Device Security Token Service (STS) also referred to as the Krypton DSTS is a micro-service written in Go. It is used to perform device authentication of devices registered for management with the Krypton system. Once devices are authenticated, a device access token is issued. This access token is signed by the DSTS and identifies the device by asserting its unique device identifier as a claim in the token.

The DSTS has the following network interfaces:
 - A REST (HTTP) endpoint - used primary for health checks, collecting metrics and for device authentication.
 - A gRPC endpoint - used for many device lifecycle management operations such as creating, modifying and deleting devices, signing keys and enrollment tokens. For a list of the operations exposed by the gRPC endpoint, view the ```dsts.proto``` file within the ```dsprotos``` folder.


## Build instructions

### Pre-requisite: docker base images
The base images required for this service are in the [Krypton Utilities - krypton-utils](https://github.com/HPInc/krypton-utils) Github repository. Make any required changes such as upgrading to newer docker base images, or updating dependencies in the ```krypton-utils``` repository. The CI for that repository will publish new updated base images to the docker registry.

**NOTE:** The docker base images are published to the [GHCR (Github Container Registry) docker repository](https://github.com/orgs/HPInc/packages) so they can be used by other Krypton service Github repositories.


### Build the DSTS docker image
Builds use Docker to create an isolated and repeatable build environment. You need to have ```docker``` and ```make``` installed on your Linux machine.

To build, type the following commands at the root of the repository:

```
make docker-image
```

### Execute unit-tests
Unit testing also uses a docker environment. To run unit tests, type the following command at the root of the repository:

```
make test
```
