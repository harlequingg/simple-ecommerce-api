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
	@migrate -path=./migrations -database=${DB_DSN} -verbose version

.PHONY: migrate_down
migrate_down:
	@migrate -path=./migrations -database=${DB_DSN} -verbose down 1
	@migrate -path=./migrations -database=${DB_DSN} -verbose version

.PHONY: migrate_version
migrate_version:
	@migrate -path=./migrations -database=${DB_DSN} -verbose version

.PHONY: migrate_force
migrate_force:
	@migrate -path=./migrations -database=${DB_DSN} -verbose force $(version)
