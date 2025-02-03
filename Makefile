.PHONY: build
build:
	@go build -o ./bin/ecom ./cmd/api

.PHONY: run
run: build
	@./bin/ecom

.PHONY: create_migration
create_migration:
	@migrate create -seq -ext=.sql -dir=./migrations $(name)

.PHONY: migrate_up
migrate_up:
	@migrate -path=./migrations -database=${DB_DSN} -verbose up

.PHONY: migrate_down
migrate_down:
	@migrate -path=./migrations -database=${DB_DSN} -verbose down 1
