###############################################################################
##                              Build stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-builder AS build-env

# Copy the source code over and build the DSTS binary.
ADD . /go/src/dsts

WORKDIR /go/src/dsts/service
RUN cp -r /usr/local/include/google/ /go/src/dsts/dstsprotos/
RUN make gosec build

###############################################################################
##                              Packaging stage
###############################################################################
FROM ghcr.io/hpinc/krypton/krypton-go-base

# set working directory
WORKDIR /go/bin

COPY --from=build-env /go/src/dsts/bin/dsts/dstsservice .
COPY --from=build-env /go/src/dsts/service/config/config.yaml .
COPY --from=build-env /go/src/dsts/service/config/registered_apps.yaml .
COPY --from=build-env /go/src/dsts/service/db/schema /go/bin/schema/

# Add AWS Root CA certs required for SSL connection to RDS service.
COPY --from=build-env /go/src/dsts/service/docker/service/global-bundle.pem /etc/ssl/certs/global-bundle.pem

USER 1001

# Expose the gRPC port over which the DSTS service listens. HTTPS required.
EXPOSE 7000

# Expose the REST port over which the DSTS service listens. HTTPS required.
EXPOSE 7001

# Start up the DSTS.
ENTRYPOINT ["/go/bin/dstsservice"]
