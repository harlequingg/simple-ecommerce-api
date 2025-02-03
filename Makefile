.PHONY: build
build:
	@go build -o ./bin/ecom ./cmd/api

.PHONY: run
run: build
	@./bin/ecom