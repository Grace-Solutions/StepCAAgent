Below is a concrete product/spec draft you can hand to engineering.

# Specification: Cross-Platform Certificate Agent Service

## 1. Overview

Build a cross-platform certificate agent service in **Go** for **Windows, macOS, and Linux** that uses **Smallstep/step libraries and platform-native APIs** to request, install, renew, and manage multiple X.509 certificates from a Step CA deployment. The Step ecosystem supports automated certificate issuance, renewal, revocation, and root distribution, and Smallstep publishes Go libraries for certificate and crypto operations that are appropriate as the implementation foundation. ([smallstep.com][1])

The agent must:

* run as a background service/daemon on all supported platforms
* manage **multiple certificate definitions** from a single JSON config file
* support config input from a **local JSON file** or a **remote URL**
* detect config replacement and reload it
* install or refresh trusted roots/intermediates
* fetch and validate CA fingerprints during bootstrap
* request and renew certificates
* place certificates and private keys into the correct OS-specific stores or files
* expose CLI commands for install, bootstrap, validation, status, and manual renewal
* protect the config file using **restrictive filesystem permissions** so that only the service account and administrators can read it

The config file is **not encrypted**. Security relies on filesystem permissions (ACLs on Windows, POSIX permissions on Linux/macOS). The administrator is responsible for ensuring that unprivileged accounts cannot read, write, or execute the config file.

Per Step guidance, renewal should prefer the certificate-based renewal flow using mTLS with the existing certificate and key where possible. Step documentation also explicitly describes root distribution/bootstrap and automated renewal as core capabilities. ([smallstep.com][2])

---

## 2. Goals

### Primary goals

* One codebase for Windows, macOS, and Linux
* Long-running service with unattended renewal
* Support for **many managed certificates** per agent
* Secure bootstrap against a Step CA using CA URL + fingerprint/root material
* OS-native certificate installation where appropriate
* Config file protected by **restrictive filesystem permissions** — only readable by the service account and administrators
* Deterministic, observable renewal behavior
* Safe rollover of roots/intermediates and end-entity certs

### Secondary goals

* Support both file-based and store-based certificate deployment targets
* Support remote config retrieval with integrity validation
* Support dry-run, validation, and inventory/reporting modes
* Minimize private key exposure and unnecessary plaintext persistence

### Non-goals

* Running a CA
* General-purpose secrets manager replacement
* Browser profile trust management beyond OS trust stores
* Full ACME server/client implementation beyond what is needed for Step-supported flows

---

## 3. Supported enrollment and renewal models

The agent should support these Step-oriented certificate lifecycle modes:

1. **Direct Step CA certificate issuance**

   * bootstrap against CA
   * authenticate using configured enrollment method
   * request a certificate
   * store/install output
   * renew using existing cert/key when supported

2. **ACME-backed issuance against Step CA**

   * useful where ACME is the desired operational model
   * Step CA supports ACME workflows and documents ACME client integration. ([smallstep.com][3])

3. **Root/intermediate trust synchronization**

   * install/update trust anchors
   * validate fingerprint or pinned root before trust changes

The implementation should prefer **certificate-based renewal** once the first certificate has been issued, because Step documents this as the simplest renewal path using mTLS with the current certificate and key. ([smallstep.com][2])

---

## 4. High-level architecture

### 4.1 Components

**A. Agent Service**

* background daemon/service
* owns config file (protected by filesystem permissions)
* performs polling, request, renewal, install, trust sync
* publishes logs/metrics/events
* maintains in-memory runtime state
* persists operational state to SQLite (WAL mode)

**B. CLI**

* same binary or companion binary
* administrative commands for:

  * install-service
  * uninstall-service
  * start/stop/restart
  * generate-sample-config
  * validate-config
  * bootstrap
  * fetch-fingerprint
  * trust install/refresh
  * request now
  * renew now
  * status
  * test-url-config

**C. Config Watcher**

* monitors local file or remote URL version/ETag/hash
* on change:

  * verify source
  * parse
  * validate
  * apply restrictive permissions to new config file
  * hot reload runtime state

**D. Certificate Workers**

* one per managed certificate or bounded worker pool
* handles lifecycle per certificate definition

**E. Platform Abstraction Layer**

* trust store operations
* key storage operations
* service installation/startup integration
* file permission hardening
* optional secure keychain/credential storage integrations

---

## 5. Operating model

### 5.1 Lifecycle

1. Agent starts
2. Verifies config file permissions are restrictive; warns/refuses if too open
3. Loads JSON config from file
4. Validates schema
5. Opens or initializes SQLite state database (WAL mode)
6. Bootstraps CA trust if needed
7. Reconciles trust stores
8. Reconciles all managed certificate definitions
9. Requests missing certificates
10. Schedules renewals before threshold
11. Watches config source and cert state continuously

### 5.2 Reconciliation behavior

The service must be declarative:

* desired state comes from config
* actual state is discovered from OS stores/files
* agent reconciles differences safely

### 5.3 Renewal threshold

Default renewal trigger:

* renew at **2/3 of certificate lifetime elapsed**, or
* renew when within configurable “renew before” window

That 2/3 pattern aligns with Step’s documented operational guidance for renewal. ([smallstep.com][2])

---

## 6. Security model

## 6.1 Threat assumptions

Protect against:

* local non-admin/non-service user reading config or state
* config tampering/replacement by unauthorized users
* MITM during bootstrap
* unauthorized trust anchor replacement
* stale or failed renewals leading to outage

Not fully protect against:

* privileged local admin/root compromise (admin is trusted)
* runtime memory scraping by fully privileged attacker
* kernel-level compromise

## 6.2 Config protection model — filesystem permissions

The config file is **plaintext JSON**. There is no encryption layer. Security relies entirely on **restrictive filesystem permissions**. The administrator is responsible for ensuring unprivileged accounts cannot read, write, or execute the config file.

**At startup and on config reload, the agent must:**

* verify the config file has appropriately restrictive permissions
* warn loudly and optionally refuse to start if the file is world-readable or accessible to non-service accounts
* apply restrictive permissions automatically when writing config (e.g., after `generate-sample-config` or when saving from remote source)

**On config file change:**

* detect change via file watcher or polling
* validate syntax and schema
* hot reload runtime state
* record audit event in state database

## 6.3 File permission requirements

**Windows**

* ACL the config file so only the service account (LocalSystem or designated service SID) and Administrators can read/write
* Remove inherited permissions that grant access to Users or Everyone
* Apply same ACL policy to state database, log files, and private key files

**macOS**

* Set file owner to root (or launchd service user) with mode `0600`
* Apply same ownership/mode to state database, log files, and private key files

**Linux**

* Set file owner to root (or systemd service user) with mode `0600`
* Apply same ownership/mode to state database, log files, and private key files
* Optionally use `0640` with a dedicated group if multiple authorized processes need read access

## 6.4 In-memory handling

* avoid logging config bodies, secret values, or private keys
* avoid unnecessary string copies of sensitive fields
* isolate secret-handling code paths

## 6.5 Integrity and authenticity of remote config

When config comes from URL, support one or more:

* pinned server CA/root/fingerprint
* detached signature validation
* signed config envelope
* mTLS fetch
* hash pinning / content digest pinning
* ETag/version awareness for reload decisions

Preferred model:

* fetch over HTTPS/mTLS
* validate detached signature
* write locally with restrictive permissions after validation

## 6.6 Trust bootstrap

Bootstrap must require at least one:

* expected root fingerprint
* pinned root cert bundle
* TOFU mode only if explicitly enabled and loudly warned

Step exposes bootstrap/trust distribution concepts and fingerprints are central to safe initial trust establishment. ([GitHub][4])

---

## 7. Functional requirements

## 7.1 Service management

The agent must support:

* install as Windows Service
* install as launchd service on macOS
* install as systemd service on Linux
* foreground mode for debugging
* service auto-start on boot
* graceful stop with in-flight operation completion or safe cancellation

## 7.2 Config ingestion

Support:

* local path
* HTTPS URL
* optional file watcher
* optional remote poll interval and ETag/Last-Modified tracking

Supported states:

* plaintext JSON (protected by filesystem permissions)
* signed JSON envelope (for remote sources)

## 7.3 Certificate definition support

Each config may define multiple certificates with:

* unique name/id
* CA endpoint
* subject/SANs
* key type and size/curve
* renewal policy
* issuance method
* target storage/install method
* hooks or reload commands where allowed
* trust requirements
* ownership/permissions rules

## 7.4 Request operations

The agent must be able to:

* request new certificate/key pairs
* optionally generate private keys locally so keys never traverse network
* submit CSR if using local keygen path
* write/install chain and key to target locations

Smallstep documents local key generation and certificate issuance as core behavior. ([GitHub][4])

## 7.5 Renewal operations

The agent must:

* inspect existing certs
* compute renewal schedule
* renew automatically
* replace/install atomically
* preserve prior version for rollback
* notify dependent applications if configured

## 7.6 Trust store operations

The agent must:

* install root CA certificates
* refresh rotated/intermediate roots
* verify fingerprint before trust changes
* avoid duplicate trust entries
* support remove/cleanup where policy allows

## 7.7 Target installation

Support these deployment targets:

**Windows**

* CurrentUser or LocalMachine certificate store
* optional PEM/PFX export to filesystem
* optional private key marked non-exportable where possible

**macOS**

* System keychain / login keychain as permitted
* PEM/P12 filesystem output
* trust insertion into System keychain with required privileges

**Linux**

* distro trust store integration abstraction
* PEM key/cert/chain files
* optional PKCS#12 output
* distro-specific trust refresh commands or native library integration layer

## 7.8 Inventory and status

Expose:

* loaded config version/hash
* CA status
* root fingerprint
* per-cert thumbprint/serial/notBefore/notAfter
* next renewal time
* last success/failure
* target location/store
* drift status

## 7.9 Logging and audit

See **Section 9 — Logging specification** for full logging architecture, rotation, permissions, and format details.

Must log:

* startup/shutdown
* bootstrap attempts
* trust changes
* certificate request/renewal attempts
* config changes/reloads
* errors and retries
* operator CLI actions

Must not log:

* raw private keys
* provisioner passwords
* bearer tokens
* config file contents

## 7.10 Metrics

Expose optional Prometheus/text or JSON metrics:

* certs managed
* certs expiring soon
* renewal success/failure counts
* config reload count
* trust sync count
* request latency
* renewal latency
* CA connectivity status

---

## 8. Configuration specification

## 8.1 Top-level schema

The config uses a top-level `Settings` key for all global/service-level configuration, and a top-level `Provisioners` array for certificate definitions. This keeps global settings cleanly separated from per-certificate provisioner definitions.

```json
{
  "Settings": {
    "version": 1,
    "serviceName": "stepcaagent",
    "pollInterval": "15m",
    "logLevel": "info",
    "logDirectory": "",
    "logMaxFiles": 3,
    "stateDirectory": "",
    "bootstrap": {
      "caUrl": "https://ca.example.com",
      "fingerprint": "SHA256:....",
      "rootBundlePath": "",
      "trustOnFirstUse": false
    },
    "configSource": {
      "type": "file",
      "path": "/etc/stepcaagent/config.json",
      "url": "",
      "headers": {},
      "mtlsProfile": "",
      "signature": {
        "required": false,
        "publicKeyPath": ""
      }
    },
    "trust": {
      "installRoots": true,
      "refreshInterval": "24h",
      "installIntermediates": true
    }
  },
  "Provisioners": []
}
```

**Field notes:**

| Field | Description |
|---|---|
| `Settings.logDirectory` | Directory for log files. Defaults to the directory containing the binary. |
| `Settings.logMaxFiles` | Maximum number of rotated log files to retain. Default `3`. Oldest files are deleted when exceeded. |
| `Settings.stateDirectory` | Directory for the SQLite state database. Defaults to the directory containing the binary. |
| `Settings.bootstrap` | CA bootstrap configuration — URL, fingerprint, root bundle. |
| `Settings.configSource` | Where the config is loaded from (file or URL) and integrity options. |
| `Settings.trust` | Global trust store sync settings. |

## 8.2 Provisioner schema (per-certificate)

Each entry in the `Provisioners` array defines one managed certificate:

```json
{
  "name": "web-api",
  "enabled": true,
  "issuer": {
    "mode": "step-ca",
    "provisioner": "svc-web",
    "profile": "default"
  },
  "subject": {
    "commonName": "web-api.example.internal",
    "dnsNames": ["web-api.example.internal"],
    "ipAddresses": [],
    "uris": [],
    "emails": []
  },
  "key": {
    "algorithm": "EC",
    "curve": "P256",
    "rsaBits": 2048,
    "generateLocally": true,
    "nonExportable": false
  },
  "renewal": {
    "mode": "auto",
    "renewBefore": "720h",
    "checkInterval": "1h",
    "jitter": "10m",
    "backoff": {
      "initial": "1m",
      "max": "1h"
    }
  },
  "storage": {
    "type": "filesystem",
    "certificatePath": "/etc/ssl/web-api.crt",
    "privateKeyPath": "/etc/ssl/private/web-api.key",
    "chainPath": "/etc/ssl/web-api-chain.crt",
    "pkcs12Path": "",
    "permissions": {
      "owner": "root",
      "group": "root",
      "fileMode": "0600"
    }
  },
  "auth": {
    "type": "provisioner-password",
    "password": "",
    "tokenPath": "",
    "jwkPath": ""
  },
  "trustBinding": {
    "installIssuedChain": true,
    "validateCaFingerprint": true
  },
  "hooks": {
    "postInstall": [],
    "postRenew": []
  }
}
```

## 8.3 Provisioner auth block

Each provisioner entry contains an `auth` sub-object for enrollment credentials. Supported auth types:

* `provisioner-password` — password string (stored in config, protected by file permissions)
* `jwk` — path to JWK/token file
* `bootstrap-token` — one-time bootstrap token
* `acme` — ACME account profile reference

Secret-bearing values (passwords, tokens) are stored in the config file which is protected by filesystem permissions. These values live in the `auth` sub-object to reduce accidental logging or serialization.

---

## 9. Logging specification

## 9.1 Logging architecture

Logging must be **centrally defined and reusable** across all packages. A single logging package (`internal/logging`) must expose a configured logger that all other packages import. There must be no ad-hoc logger creation outside this package.

## 9.2 Log file location

* **Default:** log files are written to the same directory as the agent binary
* **Customizable:** the `service.logDirectory` config field overrides the default location
* If the configured directory does not exist, the agent should attempt to create it with restrictive permissions and fail with a clear error if it cannot
* Log file names should follow the pattern: `stepcaagent.log` (current), `stepcaagent.log.1`, `stepcaagent.log.2` (rotated)

## 9.3 Log rotation and retention

* **Maximum retained files:** configurable via `service.logMaxFiles`, default `3`
* When the current log file exceeds a size threshold (default 10 MB) or on service restart, rotate:
  * rename current log to `.1`, shift existing rotated logs up (`.1` → `.2`, etc.)
  * delete the oldest file if the count exceeds `logMaxFiles`
* Rotation must be atomic where possible to avoid log loss

## 9.4 Log file permissions

* Log files must be created with restrictive permissions matching the config file permissions model (see Section 6.3)
* **Windows:** ACL log files so only the service account and Administrators can read/write
* **macOS/Linux:** set file mode `0600`, owned by the service user

## 9.5 Log format and levels

Structured logging with support for both **JSON** and **text** output modes:

* **Fields:** timestamp, level, component, certificate name (where applicable), operation, result, duration, error code/class
* **Levels:** `debug`, `info`, `warn`, `error`
* **Default level:** `info`, configurable via `service.logLevel`
* When running in foreground/debug mode, logs should also write to stderr

## 9.6 Sensitive data policy

Logs must **never** contain:

* raw private keys
* provisioner passwords or tokens
* bearer tokens
* full config file contents

Logs **may** contain:

* certificate thumbprints, serial numbers, subject names
* CA URLs and fingerprints
* file paths
* error messages (scrubbed of secrets)

---

## 10. Platform-specific requirements

## 10.1 Windows

Use:

* Windows Service APIs
* LocalMachine and CurrentUser cert stores
* NTFS ACL hardening for config, state DB, logs, and key files
* optional CNG-backed key generation if practical
* Windows resource embedding for binary icon (`resources/icons/stepcaagent.ico`)

Behavior:

* can install roots into LocalMachine Root store
* can install leaf certs into Personal/My store
* can export PEM/PFX for apps that do not consume Windows store directly
* service should run as LocalSystem by default or dedicated virtual service account

## 10.2 macOS

Use:

* launchd
* Security framework / Keychain APIs
* file ACLs
* system keychain trust modification with appropriate privileges

Behavior:

* support login/system keychain destinations
* support PEM/P12 export
* root trust changes must be auditable and privilege-gated

## 10.3 Linux

Use:

* systemd
* distro abstraction layer for trust store installation
* PEM/PKCS#12 filesystem deployment as first-class path


Behavior:

* root store support must cover major families:

  * Debian/Ubuntu
  * RHEL/CentOS/Alma/Rocky
  * SUSE
* where native distro trust manipulation differs, abstract through provider modules
* fallback to managed application-local trust bundles when system-wide trust is not permitted

---

## 11. Step library integration requirements

Use official Smallstep Go libraries where appropriate for:

* crypto/key handling
* certificate template/CSR handling
* CA interaction
* fingerprint and trust operations where available

Smallstep’s published Go crypto repository includes packages for crypto and X.509-related workflows, and the Step CA/docs describe the CA as exposing JSON/HTTPS APIs for issuance, renewal, and revocation. ([GitHub][5])

Engineering should prefer:

* official Smallstep Go packages first
* standard library crypto/x509 and tls where sufficient
* native platform APIs for trust store integration
* no shelling out to `step` CLI except as an explicitly disabled-by-default compatibility fallback

---

## 12. Failure handling

## 12.1 Request/renew failures

On failure:

* do not destroy existing valid cert
* exponential backoff with jitter
* warn when cert enters “expiring soon” state
* escalate severity as expiry approaches

## 12.2 Trust failures

* do not partially install trust without verification
* roll back failed trust writes where possible
* preserve prior trust material if replacement fails

## 12.3 Config failures

* reject invalid or unauthenticated config
* retain last known good config
* continue operating with last known good state
* surface config generation/version mismatch clearly

## 12.4 Clock skew

* detect significant local clock skew
* warn because certificate validity and renewal timing depend on correct time

---

## 13. CLI specification

Required commands:

```text
stepcaagent service install          # register as OS service
stepcaagent service uninstall        # stop (if running) + remove service; idempotent
stepcaagent service start            # start the registered service
stepcaagent service stop             # stop the running service
stepcaagent service initialize       # install + start in one step
stepcaagent service run              # run in foreground (debug mode)

stepcaagent config sample --out config.json
stepcaagent config validate --file config.json
stepcaagent config test-source --url https://...

stepcaagent bootstrap fingerprint --ca-url https://ca.example.com
stepcaagent bootstrap trust install --ca-url ... --fingerprint ...
stepcaagent bootstrap trust refresh

stepcaagent cert request --name web-api
stepcaagent cert renew --name web-api
stepcaagent cert renew --all
stepcaagent cert list
stepcaagent cert inspect --name web-api

stepcaagent status
stepcaagent doctor
```

### Service command semantics

| Command | Behavior |
|---|---|
| `install` | Register the service with the OS service manager. Idempotent — no error if already installed. |
| `uninstall` | Stop the service if running, then remove registration. Idempotent — no error if not installed. |
| `start` | Start a previously installed service. |
| `stop` | Stop a running service. |
| `initialize` | Equivalent to `install` followed by `start`. Convenience for first-time setup. |
| `run` | Run the agent in the foreground (not as a service). Useful for debugging. |

### CLI rules

* CLI must support JSON output
* CLI must support non-interactive mode
* privileged operations must fail clearly when insufficient rights
* secret values should be accepted via stdin/file/env only where explicitly allowed, and should not echo

---

## 14. Data storage

### 14.1 State database — SQLite with WAL

The agent uses **SQLite** in **WAL (Write-Ahead Logging) mode** as the state database. This is not optional.

**Location:**

* Default: same directory as the agent binary
* Customizable via `service.stateDirectory` in config
* File name: `stepcaagent.db`

**Stored data:**

* certificate inventory (thumbprint, serial, subject, notBefore, notAfter, storage location)
* renewal tracking (last attempt, last success, next scheduled, retry count)
* audit events (config changes, trust changes, cert operations, service lifecycle)
* last known good config hash/version
* CA connectivity status and last check time

**Permissions:**

* state database file must have same restrictive permissions as the config file (see Section 6.3)

### 14.2 Persist only what is needed

* config file (plaintext JSON, permission-protected)
* SQLite state database
* certificate and key files at configured storage locations
* log files

Do not persist:

* raw secret materials unless explicitly required for operation
* multiple stale private key copies

---

## 15. Concurrency model

* main reconciler loop
* bounded worker pool for cert operations
* per-certificate mutex to avoid duplicate renewal
* config reload barrier so no request uses half-applied config
* trust operations serialized globally

---

## 16. Observability

### Logs

See **Section 9 — Logging specification** for full details on log architecture, rotation, permissions, and format.

### Health/readiness

Expose optional local-only endpoints or CLI health checks:

* process alive
* config valid
* CA reachable
* trust sync healthy
* no certs expired

### Audit events (stored in SQLite state DB)

* config loaded/reloaded
* config rejected
* fingerprint changed
* trust installed/refreshed
* certificate requested/renewed/replaced

---

## 17. Packaging and distribution

Deliverables:

* single statically linked Go binaries where practical
* OS-native packages:

  * MSI for Windows
  * pkg for macOS
  * deb/rpm/tar.gz for Linux
* signed binaries
* sample configs
* admin documentation
* operational runbook

---

## 18. Testing requirements

## 18.1 Unit tests

* config parsing/validation
* file permission verification logic
* renewal scheduling
* fingerprint validation
* file watcher behavior
* logging rotation and retention
* SQLite state database operations

## 18.2 Integration tests

* against test Step CA
* initial enrollment
* renewal
* root refresh
* config replacement/reload
* per-platform store install behavior
* log file rotation under load

## 18.3 Chaos/failure tests

* CA unavailable
* expired root
* wrong fingerprint
* unreadable config
* partial file write
* permissions denied
* remote config returns bad signature
* clock skew

## 18.4 Platform matrix

* Windows Server + desktop supported versions
* current supported macOS versions
* major Linux distros

---

## 19. Acceptance criteria

The implementation is complete when:

1. A plaintext JSON config can be loaded and the agent verifies restrictive file permissions before operating.
2. The service can bootstrap trust from Step CA using pinned fingerprint/root.
3. The service can request multiple certificates from one config.
4. The service can renew certificates automatically before expiration.
5. The service can install roots and leaf certificates into correct platform targets.
6. Replacing the config file triggers validation and safe reload.
7. A remote HTTPS config source can be fetched, validated, permission-protected locally, and applied.
8. The CLI can generate a sample config, validate config, show status, and force renewal.
9. Logs are written next to the binary (or custom directory), rotated to retain the last 3 files, and permission-protected.
10. State is persisted in SQLite (WAL mode) with restrictive file permissions.
11. Logs and metrics clearly show lifecycle status without leaking secrets.
12. On failure, the service preserves last known good config and last valid installed certificates.

---

## 20. Recommended implementation decisions

These are the decisions locked in for v1:

* **Language:** Go
* **Binary name:** `stepcaagent`
* **Primary CA integration:** official Smallstep Go libraries + Go standard crypto/tls/x509 + native OS APIs
* **Config format:** plaintext JSON, protected by filesystem permissions
* **Config protection model:** restrictive file permissions (no encryption)
* **State database:** SQLite with WAL mode
* **Logging:** centralized logger, files next to binary (customizable), retain last 3, permission-protected
* **Renewal model:** automatic, default at 2/3 lifetime or configurable renew-before
* **Remote config security:** HTTPS + pinned trust + detached signature verification
* **Key generation:** local by default
* **Deployment target types:** OS store and filesystem PEM/PFX/P12
* **Service managers:** Windows Service, launchd, systemd
* **Windows binary icon:** embedded from `resources/icons/stepcaagent.ico`
* **Source code location:** `src/` directory

---

## 21. Open design questions for v1/v2

These should be decided early:

* Should v1 support only Step CA native issuance first, then ACME in v2?
* Should Linux root-store writes be system-wide only, or also support app-local trust bundles as equal first-class targets?
* Should private keys be allowed to be exportable on Windows/macOS when store-installed?
* Should remote config require signatures, or be optional in v1?
* Should hooks be allowed at all, given execution risk?

---

## 22. Suggested project structure

```text
StepCAAgent/
├── src/
│   ├── cmd/
│   │   └── stepcaagent/          # main binary entry point
│   ├── internal/
│   │   ├── bootstrap/            # CA trust bootstrap
│   │   ├── config/               # config loading, validation, watching
│   │   ├── crypto/               # key generation, CSR, cert ops
│   │   ├── enroll/               # certificate enrollment
│   │   ├── renew/                # certificate renewal
│   │   ├── trust/                # trust store operations
│   │   ├── storage/              # cert/key file deployment
│   │   ├── platform/             # OS-specific implementations
│   │   │   ├── windows/
│   │   │   ├── darwin/
│   │   │   └── linux/
│   │   ├── service/              # service install/lifecycle
│   │   ├── state/                # SQLite state DB (WAL)
│   │   ├── permissions/          # file permission enforcement
│   │   ├── metrics/              # Prometheus/JSON metrics
│   │   └── logging/              # centralized logger (all packages import this)
│   ├── pkg/
│   │   └── api/                  # public API types
│   └── go.mod
├── resources/
│   └── icons/
│       └── stepcaagent.ico       # embedded in Windows binary
├── artifacts/                    # build outputs
├── binaries/                     # release binaries
├── docs/
│   └── DesignSpecification.md
└── tests/                        # integration/e2e tests
```

---

## 23. Short executive summary

This service is a **cross-platform Go certificate lifecycle agent** (`stepcaagent`) for Step CA environments. It loads JSON config from file or URL (protected by restrictive filesystem permissions rather than encryption), bootstraps trust with fingerprint validation, requests and renews multiple certificates, and installs roots and leaf certs into the correct platform stores or files. Operational state is persisted in SQLite (WAL mode). Logging is centralized, writes next to the binary by default (customizable), retains the last 3 log files, and applies restrictive file permissions. It should be built around official Smallstep Go libraries plus OS-native trust/key APIs, with declarative reconciliation, strong auditability, and safe fallback to last known good state. Source code lives under `src/`. The Windows binary embeds an icon from `resources/icons/stepcaagent.ico`. ([smallstep.com][1])

[1]: https://smallstep.com/docs/design-document/?utm_source=chatgpt.com "step-ca Architecture & Design Document"
[2]: https://smallstep.com/blog/automate-docker-ssl-tls-certificates/?utm_source=chatgpt.com "Automating TLS certificate management in Docker"
[3]: https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/?utm_source=chatgpt.com "Configure ACME Clients with step-ca Tutorial"
[4]: https://github.com/smallstep/certificates?utm_source=chatgpt.com "smallstep/certificates: 🛡️ A private certificate authority (X. ..."
[5]: https://github.com/smallstep/crypto?utm_source=chatgpt.com "smallstep/crypto: Crypto is a collection of packages used ..."
