BINARY ?= wazuh-runtime-java-normalizer
OUTPUT ?= $(CURDIR)/$(BINARY)
GOCACHE ?= $(CURDIR)/.gocache

.PHONY: build test clean

build:
	install -d $(dir $(OUTPUT))
	GOCACHE=$(GOCACHE) go build -o $(OUTPUT) ./cmd/$(BINARY)

test:
	GOCACHE=$(GOCACHE) go test ./...

clean:
	rm -f $(CURDIR)/$(BINARY)
	rm -rf $(GOCACHE)
