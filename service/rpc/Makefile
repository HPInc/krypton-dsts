include ../common.mk
BINARY_DIR=../../bin/dsts

# Build the test binary for the RPC tests.
build-test-binaries:
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOTEST) -c \
	-o $(BINARY_DIR)/$(BINARY_NAME).test

clean:
	-rm *.cert *.key