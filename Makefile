VERSION       ?= dev
SHELL_SCRIPTS := $(shell find scripts -type f -name '*.sh')
TEST_SCRIPTS  := $(shell find tests -type f -name '*.sh')
ALL_SCRIPTS   := $(SHELL_SCRIPTS) $(TEST_SCRIPTS)
COVERAGE_DIR  := coverage

.PHONY: go-check go-test go-coverage go-vulncheck go-verify security-trivy docker-lint \
        shell-lint shell-fmt shell-test shell-coverage shell-verify secrets-scan \
        verify coverage build install uninstall clean

go-check:
	@test -z "$$(gofmt -s -l .)" || (echo "Unformatted files found. Run 'gofmt -s -w .' to fix them." && false)
	golangci-lint run ./...
	go build ./...

go-test:
	go test -v -race ./...

go-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

go-vulncheck:
	govulncheck ./...

go-verify: go-check go-test go-vulncheck

shell-lint:
	shellcheck --enable=all -x $(ALL_SCRIPTS)
	shfmt -d -s -i 2 $(ALL_SCRIPTS)
	checkbashisms -f $(ALL_SCRIPTS) || true

shell-fmt:
	shfmt -w -s -i 2 $(ALL_SCRIPTS)

shell-test:
	bashunit tests/

shell-coverage:
	rm -rf $(COVERAGE_DIR)
	bashunit tests/ --coverage --coverage-paths scripts

shell-verify: shell-lint shell-test

docker-lint:
	hadolint docker/Dockerfile

security-trivy:
	trivy fs --severity CRITICAL,HIGH .

secrets-scan:
	gitleaks detect --source . --no-git --no-color

verify: go-verify shell-verify docker-lint security-trivy secrets-scan

coverage: go-coverage shell-coverage

build:
	go build -ldflags "-s -w -X main.Version=$(VERSION)" -o crowdsec-cloudflare-list-bouncer ./cmd/crowdsec-cloudflare-list-bouncer

install: build
	install -d /usr/local/bin /etc/default /etc/crowdsec/bouncers/cloudflare-list-targets.d /etc/systemd/system
	install -m 500 crowdsec-cloudflare-list-bouncer /usr/local/bin/
	install -m 400 config/crowdsec-cloudflare-list-bouncer.default /etc/default/crowdsec-cloudflare-list-bouncer
	install -m 400 config/crowdsec-cloudflare-list-bouncer.yaml /etc/crowdsec/bouncers/
	install -m 400 config/cloudflare-list-targets.d/example.yaml /etc/crowdsec/bouncers/cloudflare-list-targets.d/main.yaml
	install -m 644 systemd/crowdsec-cloudflare-list-bouncer.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable crowdsec-cloudflare-list-bouncer

uninstall:
	systemctl disable --now crowdsec-cloudflare-list-bouncer 2>/dev/null || true
	rm -f /usr/local/bin/crowdsec-cloudflare-list-bouncer
	rm -f /etc/systemd/system/crowdsec-cloudflare-list-bouncer.service
	systemctl daemon-reload

clean:
	rm -rf $(COVERAGE_DIR) .bashunit coverage.out dist
