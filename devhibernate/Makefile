BINARY := bin/devhibernate

.PHONY: all fmt fmt-check vet test race build verify clean

all: verify

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "Files need gofmt:"; gofmt -l .; exit 1)

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

build:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X main.version=0.1.0-dev" -o $(BINARY) ./cmd/devhibernate

verify: fmt-check vet race build

clean:
	rm -rf bin
