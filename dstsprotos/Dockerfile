###############################################################################
##                              Build stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-builder AS build-env

ADD . /go/src/dstsprotos
WORKDIR /go/src/dstsprotos

# build the source
RUN make build-proto

###############################################################################
##                              Packaging stage
###############################################################################
FROM scratch

WORKDIR /protos
COPY --from=build-env /go/src/dstsprotos/*.pb.go /protos/
