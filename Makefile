.PHONY: ci vet test build

ci: vet test build

vet:
	go vet ./...

test:
	go test ./...

build:
	go build ./...
