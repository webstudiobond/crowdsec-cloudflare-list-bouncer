# CrowdSec Cloudflare List Bouncer

[![CI](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/webstudiobond/crowdsec-cloudflare-list-bouncer?label=Release&include_prereleases)](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/webstudiobond/crowdsec-cloudflare-list-bouncer)](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/webstudiobond/crowdsec-cloudflare-list-bouncer)](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/issues)
[![GitHub repo size](https://img.shields.io/github/repo-size/webstudiobond/crowdsec-cloudflare-list-bouncer)](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Synchronizes [CrowdSec](https://www.crowdsec.net/) LAPI decisions into [Cloudflare](https://www.cloudflare.com/) Account-level IP Lists to block malicious traffic at the Cloudflare Anycast edge before it reaches origin infrastructure.

## Motivation

* **Tooling Availability:** No actively maintained bouncer exists, at least none that we could find, for synchronizing CrowdSec decisions directly with Cloudflare IP Lists via the REST API.
* **Cloudflare Free Tier Limitations:** The officially supported bouncer relies on Cloudflare Workers. On Free Tier accounts, daily worker request limits are quickly exhausted by bot traffic and scanners, risking broken site access or lost protection once the limit is reached.

## Architecture Highlights

* **Edge Firewall Integration:** Evaluates traffic at line rate with zero latency overhead and zero request quota consumption using Cloudflare Account-level IP Lists and a single WAF rule: `ip.src in $crowdsec`.
* **Zero External Dependencies:** Built exclusively with the Go standard library, eliminating third-party supply-chain risks and producing a minimal, self-contained static binary.
* **Multi-Target Routing & Filtering:** Distributes decisions from a single CrowdSec LAPI stream to multiple Cloudflare accounts and lists with granular origin filtering for local and community blocklists.
* **Address Validation & Normalization:** Enforces valid CIDR prefix boundaries and automatically normalizes single IPv6 addresses to `/64` subnets.
* **Rate Limiting & Backoff:** Handles Cloudflare API rate limits, write collisions, and transient errors using exponential backoff with jitter.
* **Hardened Security Profile:** Enforces strict least-privilege file permissions and full systemd service sandboxing.
* **Pre-flight Verification:** Validates configuration syntax, API tokens, and list accessibility before starting the daemon.

---

<details>
<summary><strong>Production Directory Structure</strong></summary>

```text
/
├── etc/
│   ├── default/
│   │   └── crowdsec-cloudflare-list-bouncer             # Environment file with secrets - 0400
│   ├── crowdsec/
│   │   └── bouncers/
│   │       ├── crowdsec-cloudflare-list-bouncer.yaml    # Main daemon configuration - 0400
│   │       └── cloudflare-list-targets.d/               # Target configurations directory - 0700
│   │           └── main.yaml                            # Target configuration - 0400
│   └── systemd/
│       └── system/
│           └── crowdsec-cloudflare-list-bouncer.service # Systemd service unit - 0644
└── usr/
    └── bin/
        └── crowdsec-cloudflare-list-bouncer             # Static binary - 0500
```

</details>

---

<details>
<summary><strong>Deployment &amp; Setup</strong></summary>

### Prerequisites

#### Cloudflare
* **API Token:** Create a custom token at [API Tokens](https://dash.cloudflare.com/profile/api-tokens) with `Account Filter Lists:Edit` permission scoped to your account.
* **Account ID:** Found in the dashboard URL `https://dash.cloudflare.com/<ACCOUNT_ID>/...` or the zone overview sidebar.
* **List ID:** Create an IP list named `crowdsec` with `IP addresses` content type under **Manage Account** > **Configurations** > **Lists** and copy its 32-character ID.

#### CrowdSec
Generate a Local API key on your CrowdSec server:

```bash
sudo cscli bouncers add cloudflare-list-bouncer
```

---

### Installation

#### Package Repository (Recommended)

Add the official repository to receive seamless updates via standard system package managers.

**Debian / Ubuntu:**

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://webstudiobond.github.io/crowdsec-cloudflare-list-bouncer/webstudiobond.gpg | sudo tee /etc/apt/keyrings/webstudiobond.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/webstudiobond.gpg] https://webstudiobond.github.io/crowdsec-cloudflare-list-bouncer/deb stable main" | sudo tee /etc/apt/sources.list.d/crowdsec-cloudflare-list-bouncer.list
sudo apt update
sudo apt install crowdsec-cloudflare-list-bouncer
```

**RHEL / Fedora / CentOS / AlmaLinux:**

```bash
sudo tee /etc/yum.repos.d/crowdsec-cloudflare-list-bouncer.repo << 'EOF'
[crowdsec-cloudflare-list-bouncer]
name=CrowdSec Cloudflare List Bouncer
baseurl=https://webstudiobond.github.io/crowdsec-cloudflare-list-bouncer/rpm/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://webstudiobond.github.io/crowdsec-cloudflare-list-bouncer/webstudiobond.gpg
EOF
sudo dnf install crowdsec-cloudflare-list-bouncer
```

#### Automated Script

Run the automated installer script to detect your platform architecture, verify SHA256 checksums from GitHub Releases, and install the package:

```bash
curl -fSsL https://raw.githubusercontent.com/webstudiobond/crowdsec-cloudflare-list-bouncer/main/scripts/install.sh | sudo bash
```

#### Manual Download & Verification

Download the latest package from [Releases](https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/releases), verify its SHA256 digest from the GitHub API, and install:

Debian / Ubuntu:

```bash
curl -fSsLO https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/releases/latest/download/crowdsec-cloudflare-list-bouncer_<version>_<arch>.deb
EXPECTED_HASH=$(curl -fSs https://api.github.com/repos/webstudiobond/crowdsec-cloudflare-list-bouncer/releases/latest | jq -r '.assets[] | select(.name == "crowdsec-cloudflare-list-bouncer_<version>_<arch>.deb") | .digest' | sed 's/sha256://')
echo "${EXPECTED_HASH}  crowdsec-cloudflare-list-bouncer_<version>_<arch>.deb" | sha256sum -c -
sudo dpkg -i crowdsec-cloudflare-list-bouncer_<version>_<arch>.deb
```

RHEL / Fedora / AlmaLinux:

```bash
curl -fSsLO https://github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/releases/latest/download/crowdsec-cloudflare-list-bouncer-<version>.<arch>.rpm
EXPECTED_HASH=$(curl -fSs https://api.github.com/repos/webstudiobond/crowdsec-cloudflare-list-bouncer/releases/latest | jq -r '.assets[] | select(.name == "crowdsec-cloudflare-list-bouncer-<version>.<arch>.rpm") | .digest' | sed 's/sha256://')
echo "${EXPECTED_HASH}  crowdsec-cloudflare-list-bouncer-<version>.<arch>.rpm" | sha256sum -c -
sudo rpm -Uvh crowdsec-cloudflare-list-bouncer-<version>.<arch>.rpm
```

For manual binary installation or building from source, refer to [DEVELOPMENT](DEVELOPMENT.md).

---

### Configuration

Configuration files are installed with `0400` permissions. Full syntax and options are documented in the repository templates under [`config/`](config/).

#### 1. Secrets Environment File
Define `CS_LAPI_KEY`, `CF_API_TOKEN`, `CF_ACCOUNT_ID`, and `CF_BAN_LIST_ID` in `/etc/default/crowdsec-cloudflare-list-bouncer`. Reference template: [`config/crowdsec-cloudflare-list-bouncer.default`](config/crowdsec-cloudflare-list-bouncer.default).

```bash
sudo nano /etc/default/crowdsec-cloudflare-list-bouncer
```

#### 2. Main Daemon Configuration
Configure daemon parameters such as `api_url`, `poll_interval`, and logging in `/etc/crowdsec/bouncers/crowdsec-cloudflare-list-bouncer.yaml`. Reference template: [`config/crowdsec-cloudflare-list-bouncer.yaml`](config/crowdsec-cloudflare-list-bouncer.yaml).

```bash
sudo nano /etc/crowdsec/bouncers/crowdsec-cloudflare-list-bouncer.yaml
```

#### 3. Target Configuration
Configure Cloudflare list targets, allowed origins, and decision types in `/etc/crowdsec/bouncers/cloudflare-list-targets.d/main.yaml`. Reference template: [`config/cloudflare-list-targets.d/example.yaml`](config/cloudflare-list-targets.d/example.yaml).

```bash
sudo nano /etc/crowdsec/bouncers/cloudflare-list-targets.d/main.yaml
```

To connect an additional Cloudflare account or list, duplicate this file:

```bash
sudo cp /etc/crowdsec/bouncers/cloudflare-list-targets.d/main.yaml /etc/crowdsec/bouncers/cloudflare-list-targets.d/secondary.yaml
sudo chmod 0400 /etc/crowdsec/bouncers/cloudflare-list-targets.d/*.yaml
```

---

### Service Management

The systemd service unit runs automated pre-flight validation before starting:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crowdsec-cloudflare-list-bouncer.service
sudo systemctl status crowdsec-cloudflare-list-bouncer.service
```

Monitor live service logs:

```bash
sudo journalctl -u crowdsec-cloudflare-list-bouncer.service -f
```

---

### Uninstallation

#### Debian / Ubuntu

Remove the service and binary while preserving configuration files:

```bash
sudo dpkg -r crowdsec-cloudflare-list-bouncer
```

Purge the package and remove all configuration files:

```bash
sudo dpkg -P crowdsec-cloudflare-list-bouncer
```

#### RHEL / Fedora / AlmaLinux

Remove the package:

```bash
sudo rpm -e crowdsec-cloudflare-list-bouncer
```

</details>

---

<details>
<summary><strong>Cloudflare WAF Rule Configuration</strong></summary>

Create a WAF Custom Rule in your zone (**Security** > **WAF** > **Custom rules**):

* **Rule name:** `CrowdSec`
* **Expression:** `ip.src in $crowdsec`
* **Action:** `Block` or `Managed Challenge`

Click **Deploy** to activate edge enforcement.

</details>

---

## Development & Testing

For instructions on building from source, running the test suite, and local verification gates, refer to [DEVELOPMENT](DEVELOPMENT.md).
