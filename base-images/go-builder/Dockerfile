FROM golang:1.24.4-alpine3.22 AS stage

ENV PROTOBUF_URL=https://github.com/protocolbuffers/protobuf/releases/download/v31.1/protoc-31.1-linux-x86_64.zip
RUN apk add curl && \
    curl -sLo /tmp/protobuf.zip ${PROTOBUF_URL} && \
    unzip /tmp/protobuf.zip -d /tmp && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest

## final
FROM golang:1.24.4-alpine3.22
RUN apk add --no-cache git alpine-sdk gcompat brotli-dev \
    coreutils openssl curl jq bash shellcheck
COPY --from=stage /go/bin/protoc-gen-go /usr/local/bin
COPY --from=stage /go/bin/protoc-gen-go-grpc /usr/local/bin
COPY --from=stage /tmp/bin/protoc /usr/local/bin
COPY --from=stage /tmp/include /usr/local/include
COPY --from=stage /go/bin/gosec /usr/local/bin
