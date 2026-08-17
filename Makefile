.PHONY: build test clean

build:
	go build -o bin/cipher-shield ./cmd/server/
	go build -o bin/cipher-shield-proxy ./cmd/proxy/

test:
	go test ./...

clean:
	rm -rf bin/
