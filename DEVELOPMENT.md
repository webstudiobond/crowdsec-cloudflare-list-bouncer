# CrowdSec Cloudflare List Bouncer Development Guide

This guide covers local development, code validation, testing standards, build workflows, and end-to-end testing on a remote server running CrowdSec.

---

## 1. Prerequisites

Ensure the following tools and dependencies are installed prior to local development and validation:

- **Git**
- **Go 1.27+**
- **GNU Make**
- **Docker**
- **golangci-lint**
- **govulncheck**
- **trivy**
- **hadolint**
- **bashunit**
- **shellcheck**
- **shfmt**
- **checkbashisms**
- **gitleaks**
- **nfpm** (optional, for `.deb` and `.rpm` packaging)

---

## 2. Repository Initialization

1. **Clone the repository:**
   ```bash
   git clone https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer
   cd crowdsec-cloudflare-list-bouncer
   ```

2. **Verify tooling availability:**
   ```bash
   go version
   golangci-lint --version
   hadolint --version
   shellcheck --version
   shfmt --version
   checkbashisms --version
   gitleaks version
   bashunit --version
   ```

---

## 3. Code Validation & Testing

The project enforces strict code quality and security standards across all Go source files, shell scripts, and manifests. All validation workflows are centralized in the `Makefile`.

1. **Go Formatting, Linting & Compilation Verification:**
   Validates Go code formatting via `gofmt -s`, runs all 46 active linters configured in `.golangci.yml`, and verifies compilation:
   ```bash
   make go-check
   ```

2. **Go Unit Tests (with Race Detector):**
   Executes all Go unit tests with the race detector enabled (`-race`):
   ```bash
   make go-test
   ```

3. **Go Code Coverage:**
   Executes Go unit tests and displays per-function coverage statistics:
   ```bash
   make go-coverage
   ```

4. **Go Vulnerability Scanning & Sequential Go Verification:**
   Scans Go source code for known CVEs using `govulncheck`:
   ```bash
   make go-vulncheck
   ```
   To sequentially execute all Go quality gates (`go-check`, `go-test`, `go-vulncheck`):
   ```bash
   make go-verify
   ```

5. **Filesystem Security Scanning:**
   Audits the repository filesystem for vulnerabilities using `trivy`:
   ```bash
   make security-trivy
   ```

6. **Shell Script Linting & Formatting:**
   Analyzes all scripts and tests with `shellcheck --enable=all`, verifies formatting diffs with `shfmt -d`, and checks portability with `checkbashisms`:
   ```bash
   make shell-lint
   ```
   To automatically format all shell scripts in-place using `shfmt`:
   ```bash
   make shell-fmt
   ```

7. **Shell Unit Testing & Coverage:**
   Executes the shell test suite using `bashunit`:
   ```bash
   make shell-test
   ```
   To run shell unit tests and generate line coverage reports in `coverage/`:
   ```bash
   make shell-coverage
   ```
   To sequentially run shell linting and shell tests:
   ```bash
   make shell-verify
   ```

8. **Secret Scanning:**
   Scans the repository for committed credentials, API tokens, or secrets via `gitleaks`:
   ```bash
   make secrets-scan
   ```

9. **Container Image Linting:**
   Lints `docker/Dockerfile` for security and best practices via `hadolint`:
   ```bash
   make docker-lint
   ```

10. **Comprehensive Project Verification:**
    Executes the entire validation suite (`go-verify`, `shell-verify`, `docker-lint`, `security-trivy`, `secrets-scan`). **Run this command prior to opening a pull request or releasing:**
    ```bash
    make verify
    ```

11. **Unified Test Coverage:**
    Executes both Go unit test coverage (`go-coverage`) and shell unit test coverage (`shell-coverage`):
    ```bash
    make coverage
    ```

12. **Clean Build & Test Artifacts:**
    Removes test coverage reports, runner cache, and build binaries:
    ```bash
    make clean
    ```

---

## 4. Build Workflow

1. **Compile local binary:**
   ```bash
   make build
   ```
   Produces the `crowdsec-cloudflare-list-bouncer` executable in the repository root.

2. **Inject a specific release version (Optional):**
   ```bash
   make build VERSION=1.0.0
   ```

3. **Cross-compile for remote architectures:**
   You can cross-compile for any target platform by passing standard Go environment variables:
   ```bash
   # Linux AMD64 (x86_64):
   GOOS=linux GOARCH=amd64 make build VERSION=1.0.0

   # Linux ARM64 (aarch64):
   GOOS=linux GOARCH=arm64 make build VERSION=1.0.0
   ```

4. **Build Docker container image:**
   Build the minimal container image based on `scratch`:
   ```bash
   docker build -f docker/Dockerfile -t crowdsec-cloudflare-list-bouncer:dev .
   ```

5. **Build Linux packages (.deb and .rpm) with NFPM:**
   ```bash
   VERSION=1.0.0 ARCH=amd64 nfpm package --packager deb --target dist/
   VERSION=1.0.0 ARCH=amd64 nfpm package --packager rpm --target dist/
   ```

---

## 5. Remote Server Testing & Deployment

This section details manual deployment and end-to-end testing on a remote Linux server running CrowdSec.

### 5.1 Cloudflare Prerequisites

Before deploying the bouncer, ensure you have gathered the required credentials (`CF_API_TOKEN`, `CF_ACCOUNT_ID`, and `CF_BAN_LIST_ID`). Detailed step-by-step instructions for creating the API token, locating your Account ID, and provisioning an IP list are provided in [README.md - Cloudflare Prerequisites](README.md#cloudflare-prerequisites).

### 5.2 Register Bouncer in CrowdSec

On the remote server, generate a dedicated LAPI key for the bouncer:
```bash
sudo cscli bouncers add cloudflare-list-bouncer
```
Save the generated API key displayed in the output (`CS_LAPI_KEY`).

### 5.3 File Placement & Permissions

Strict permissions follow the Principle of Least Privilege (Security Hardening):
- Binaries are marked `0500` (`r-x------`) — executable only by `root`, non-writable.
- Secrets and configs are marked `0400` (`r--------`) — read-only by `root`, non-writable.

| Source File | Destination on Server | Permissions | Ownership | Description |
| :--- | :--- | :--- | :--- | :--- |
| `crowdsec-cloudflare-list-bouncer` | `/usr/local/bin/crowdsec-cloudflare-list-bouncer` | `0500` | `root:root` | Binary executable |
| `config/crowdsec-cloudflare-list-bouncer.default` | `/etc/default/crowdsec-cloudflare-list-bouncer` | `0400` | `root:root` | Secrets environment file |
| `config/crowdsec-cloudflare-list-bouncer.yaml` | `/etc/crowdsec/bouncers/crowdsec-cloudflare-list-bouncer.yaml` | `0400` | `root:root` | Main configuration |
| `config/cloudflare-list-targets.d/` | `/etc/crowdsec/bouncers/cloudflare-list-targets.d/` | `0700` | `root:root` | Targets directory |
| `config/cloudflare-list-targets.d/example.yaml` | `/etc/crowdsec/bouncers/cloudflare-list-targets.d/main.yaml` | `0400` | `root:root` | Target configuration |
| `systemd/crowdsec-cloudflare-list-bouncer.service` | `/etc/systemd/system/crowdsec-cloudflare-list-bouncer.service` | `0644` | `root:root` | Systemd service unit |

### 5.4 Configure Credentials & Targets

Configure the installed files according to your environment (detailed options and full syntax are documented in [README.md - Configuration](README.md#configuration)):

1. **Secrets (`/etc/default/crowdsec-cloudflare-list-bouncer`)**:
   - Specify `CS_LAPI_KEY` (from step 5.2).
   - Specify target credentials: `CF_API_TOKEN`, `CF_ACCOUNT_ID`, and `CF_BAN_LIST_ID` (from step 5.1).

2. **Daemon Configuration (`/etc/crowdsec/bouncers/crowdsec-cloudflare-list-bouncer.yaml`)**:
   - Verify CrowdSec LAPI URL (`api_url`), polling interval (`poll_interval`), and logging settings.

3. **Target Definitions (`/etc/crowdsec/bouncers/cloudflare-list-targets.d/*.yaml`)**:
   - Configure target Cloudflare parameters, comment prefix, and decision filtering (`allowed_origins`, `allowed_decision_types`).

### 5.5 Verification & End-to-End Testing

1. **Start under Systemd:**
   Systemd automatically loads the environment file (`/etc/default/crowdsec-cloudflare-list-bouncer`) and executes the pre-flight check (`-t`) via `ExecStartPre` prior to starting the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now crowdsec-cloudflare-list-bouncer.service
   sudo systemctl status crowdsec-cloudflare-list-bouncer.service
   ```

2. **Monitor Live Logs:**
   ```bash
   sudo journalctl -u crowdsec-cloudflare-list-bouncer.service -f
   ```

3. **Test IPv4 Ban Addition:**
   ```bash
   sudo cscli decisions add -i 198.51.100.42 -d 5m --reason "test-manual-ban"
   ```
   Verify `journalctl` displays:
   ```
   level=INFO msg="added IP to cloudflare list" target=production-account ip=198.51.100.42 origin=cscli reason=test-manual-ban
   ```
   Check Cloudflare Dashboard: list contains `198.51.100.42` with comment `crowdsec:test-manual-ban`.

4. **Test IPv6 /64 CIDR Normalization:**
   ```bash
   sudo cscli decisions add -i 2001:db8:1111:2222:3333:4444:5555:6666 -d 5m --reason "test-ipv6-ban"
   ```
   Verify Cloudflare list receives `2001:db8:1111:2222::/64` (host bits cleared and masked to `/64`).

5. **Test Unban / Expiration:**
   ```bash
   sudo cscli decisions delete -i 198.51.100.42
   ```
   Verify `journalctl` displays:
   ```
   level=INFO msg="removed IP from cloudflare list" target=production-account ip=198.51.100.42 origin=cscli reason=test-manual-ban
   ```
   Check Cloudflare Dashboard: IP is removed from list.

   Clean up the IPv6 ban:
   ```bash
   sudo cscli decisions delete -i 2001:db8:1111:2222:3333:4444:5555:6666
   ```

---

## 6. Makefile Targets Reference

| Target | Description |
| :--- | :--- |
| `make go-check` | Validates Go formatting with `gofmt -s`, runs `golangci-lint`, and verifies compilation. |
| `make go-test` | Executes Go unit tests with race detection enabled (`-race`). |
| `make go-coverage` | Generates a Go code coverage profile and displays per-function statistics. |
| `make go-vulncheck` | Analyzes Go source code and dependencies for known CVEs using `govulncheck`. |
| `make go-verify` | Sequentially executes `go-check`, `go-test`, and `go-vulncheck`. |
| `make security-trivy` | Scans the repository filesystem for `CRITICAL` and `HIGH` severity vulnerabilities using `trivy`. |
| `make docker-lint` | Lints `docker/Dockerfile` for security and best practices via `hadolint`. |
| `make shell-lint` | Analyzes scripts and test files with `shellcheck`, verifies formatting diffs with `shfmt -d`, and checks portability with `checkbashisms`. |
| `make shell-fmt` | Automatically formats all shell scripts and test files in-place using `shfmt -w -s -i 2`. |
| `make shell-test` | Executes the complete shell unit test suite using `bashunit tests/`. |
| `make shell-coverage` | Runs shell unit tests and generates line coverage reports in `coverage/lcov.info`. |
| `make shell-verify` | Sequentially executes `shell-lint` and `shell-test`. |
| `make secrets-scan` | Scans the repository for committed secrets, tokens, and credentials using `gitleaks`. |
| `make verify` | Full quality gate executing `go-verify`, `shell-verify`, `docker-lint`, `security-trivy`, and `secrets-scan`. **Must be executed prior to submitting a pull request.** |
| `make coverage` | Sequentially executes `go-coverage` and `shell-coverage`. |
| `make build` | Builds the daemon executable. Accepts optional `VERSION`, `GOOS`, and `GOARCH`. |
| `make install` | Installs the binary, default configuration, and systemd service on the host system. |
| `make uninstall` | Stops and disables the service, removing installed systemd unit and binary files. |
| `make clean` | Removes test coverage reports (`coverage/`, `coverage.out`), test runner cache (`.bashunit/`), and distribution packages (`dist/`). |
