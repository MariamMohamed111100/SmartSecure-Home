.PHONY: setup up down logs ps smoke test lint clean

setup:        ## Generate .env secrets, TLS certs, MQTT users (safe to re-run)
	./scripts/setup.sh

up:           ## Build and start everything
	@test -f .env || ./scripts/setup.sh
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=50

ps:
	docker compose ps

smoke:        ## Verify every service is alive over MQTT/TLS
	./scripts/smoke-test.sh

test:
	pip install -q -e libs/common pytest jsonschema pyyaml && pytest libs/common/tests -q

lint:
	ruff check .

clean:        ## Stop and delete volumes (DB data is lost)
	docker compose down -v
