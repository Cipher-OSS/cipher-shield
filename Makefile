.PHONY: build test clean

build:
	go build -o bin/cipher-shield ./cmd/shield/
	go build -o bin/shield-server ./cmd/server/

test:
	go test ./...

clean:
	rm -rf bin/
