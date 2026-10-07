.PHONY: setup up down logs ps smoke test lint clean sim-list sim watch

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
	pip install -q -e libs/common pytest jsonschema pyyaml gpiozero \
	  && pytest libs/common/tests services/simulators/tests -q

lint:
	ruff check .

sim-list:     ## List simulator scenarios
	docker compose exec simulators python scenario_runner.py --list

sim:          ## Run a scenario:  make sim S=night_intruder
	@test -n "$(S)" || { echo "usage: make sim S=<scenario>  (see: make sim-list)"; exit 1; }
	docker compose exec simulators python scenario_runner.py $(S)

watch:        ## Live-print events:  make watch  (or T='home/#' for everything)
	./scripts/watch.sh $(T)

clean:        ## Stop and delete volumes (DB data is lost)
	docker compose down -v
