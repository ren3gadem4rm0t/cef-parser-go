.PHONY: all build test lint fmt check-fmt clean coverage vet ast staticcheck
.DEFAULT_GOAL := all

test:
	@go test -v ./...

lint:
	@golangci-lint run

fmt:
	@gofmt -s -w .

check-fmt:
	@gofmt -l . | tee /dev/stderr | grep -q '^' && echo "Code is not formatted" && exit 1 || echo "Code is formatted"

coverage:
	@go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out -o coverage.html

vet:
	@go vet ./...

staticcheck:
	@staticcheck ./...

ast:
	@gosec ./parser/... examples/...

clean:
	@go clean
	@rm -f ./coverage.out ./coverage.html

all: test lint fmt vet staticcheck ast
