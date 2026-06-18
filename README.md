# Honeypot - Multi-Protocol UDP Amplification Research Platform

A Go honeypot that emulates UDP amplification vectors (DNS, NTP, SSDP, CHARGEN) and runs
A/B experiments comparing response strategies (e.g. minimal vs. amplified replies) to study
attacker/scanner behaviour. Built for controlled research/lab use - see
[Safety & Ethics](#safety--ethics) before deploying anywhere reachable from the internet.

For a full hands-on walkthrough (building, starting experiments, testing the rate limiter,
verifying scanner classification), see [EXPERIMENT_GUIDE.md](EXPERIMENT_GUIDE.md).

## Research Questions

This platform exists to answer:

**RQ2: How can honeypot design choices be systematically evaluated through A/B testing?**

- **SQ1** - Do attackers interact more with honeypots that return larger responses, even if
  those responses are less realistic? *(addressed by the `minimal` vs `amplified` response
  modes and per-protocol `response_size_bytes`/TTL/padding overrides - see
  [A/B Experiments](#ab-experiments))*
- **SQ2** - Do attackers behave differently toward hosts exposing one service versus multiple
  amplification services? *(addressed by running DNS/NTP/SSDP/CHARGEN independently or
  together on the same `HONEYPOT_IPS` and comparing classification/engagement per protocol)*
- **SQ3** - Which rate-limiting strategy reduces outgoing traffic the most while still
  preserving useful information about scans and probes? *(addressed by the per-source-IP
  token-bucket rate limiter - see [Per-source-IP rate limiting](#what-it-does) and the rate
  limiter tests)*
- **SQ4** - Does the network where the honeypot is deployed influence how quickly it is
  discovered? *(addressed by deploying the same experiment configuration across networks and
  comparing time-to-first-probe via `/stats/timeseries` and `/events`)*

## What it does

The honeypot binds fake DNS, NTP, SSDP and CHARGEN servers on one or more IPs and answers
probes the way a real misconfigured service might - including with deliberately oversized
("amplified") replies. Every interaction is logged with source/destination IP, response size,
amplification factor, and a classification (`scanner` / `attacker` / `noise`). A REST API lets
you spin up "experiments" that assign different response configurations to different honeypot
IPs (or source IPs) and compare results live, without restarting the server.

Key capabilities:

- **Multi-protocol amplification emulation** - DNS (port 53), NTP (123), SSDP (1900), CHARGEN (19)
- **A/B experiment framework** - define variants per protocol (`minimal` vs `amplified`,
  configurable TTL/padding/peer counts) and assign them either by destination IP (sticky per
  honeypot IP) or by source IP (sticky per attacker, hash-based)
- **Per-source-IP rate limiting** - token bucket (burst 25, refill 1/s) per protocol
- **Scanner/attacker/noise classification** - known Shodan/Censys/ZMap IP prefixes, request-rate
  heuristics, and suspicious query types (e.g. DNS `ANY`)
- **Event persistence** - JSON Lines file or in-memory, queryable via the REST API
- **Monitoring dashboard** - single-page HTML dashboard served at `/dashboard`
- **YAML-driven experiment bootstrap** - preload experiments from a file at startup

## Architecture

Hexagonal/clean architecture, organised by dependency direction (domain has no outward
dependencies):

```
cmd/
  server/             entrypoint - wires config from env vars and starts the app
  multi_spoof_test/    standalone tool for manual spoofed-source NTP load testing

internal/
  domain/
    models/           plain data types (DNSEvent, NTPConfig, Experiment, Variant, ...)
    services/         pure protocol logic - builds DNS/NTP/SSDP/CHARGEN responses, classifies probes
  usecases/           one type per use case (HandleDNSQueryUsecase, CreateExperimentUsecase, ...)
                       orchestrates domain services + ports, no I/O details
  ports/               interfaces the usecases depend on (Logger, *EventRepository, RateLimiter, Classifier, ExperimentRepository, AssignmentRepository)
  adapters/
    servers/           UDP listeners per protocol (DNSServer, NTPServer, SSDPServer, ChargenServer)
    handlers/           glue between a server and its usecase
    persistence/        in-memory + JSONL repository implementations
    ratelimit/           token-bucket implementation (golang.org/x/time/rate) + no-op variant
    logging/             console logger
    api/                 CoordinatorServer (REST API) + dashboard HTML
  app/                  Application: wires everything together from Config, Start/Stop lifecycle

scripts/                scapy-based spoofing/load-test scripts for the experiment guide (lab-only)
experiments.yaml         example experiments auto-loaded at startup (see below)
compose.yml             docker-compose for the loadgen container
Dockerfile / Dockerfile.loadgen
```

## Requirements

- Go 1.25+ (see [go.mod](go.mod)). If you're building inside WSL, run `go version` first -
  Ubuntu's `apt` package can resolve to a much older gccgo build (e.g. `go1.16.5 gccgo`) that
  won't satisfy the `go 1.25.0` directive in go.mod. The native Windows and standard Linux/macOS
  toolchains both work fine.
- Linux/macOS recommended for binding privileged ports (53, 123, 1900, 19) - use `sudo` or
  remap ports via env vars for local testing without root
- **Windows**: privileged ports also require an elevated (Run as Administrator) terminal. Even
  elevated, port 1900 is almost always already held by the built-in "SSDP Discovery" Windows
  service and 5353 by the mDNS responder - remap `SSDP_PORT`/`DNS_PORT` (see below) rather than
  trying to free those up
- Docker + Docker Compose (optional, for the loadgen container)
- The scapy-based scripts in `scripts/` need raw/spoofed sockets and are Linux-only - run them
  from WSL or a Linux VM rather than native Windows

## Build

```bash
go build -o honeypot ./cmd/server
```

On Windows, build with an explicit `.exe` suffix if you intend to launch it directly from
PowerShell/cmd rather than Git Bash/WSL - `go build -o honeypot.exe ./cmd/server`. PowerShell
refuses to execute a file without a recognised extension (`Cannot run a document in the middle
of a pipeline`).

## Run

```bash
HONEYPOT_IPS="127.0.0.1,127.0.0.2" \
DNS_PORT=53 \
EVENTS_FILE=/tmp/honeypot_events.jsonl \
./honeypot
```

One UDP listener per protocol is started for **each** IP in `HONEYPOT_IPS`. The HTTP
coordinator/API always binds once, to `COORDINATOR_ADDR`. On success you'll see one `[INFO]`
line per server, e.g.:

```
[INFO] Honeypot application starting
[INFO] Starting coordinator HTTP server on 0.0.0.0:8080
[INFO] Starting DNS honeypot server on 127.0.0.1:53
[INFO] Starting NTP honeypot server on 127.0.0.1:123
[INFO] Starting SSDP honeypot server on 127.0.0.1:1900
[INFO] Starting CHARGEN honeypot server on 127.0.0.1:19
```

A `[ERROR] Failed to listen on UDP for ...: bind: ...` line right after means something else
already owns that port (or you lack permission) - see [Environment variables](#environment-variables)
for remapping.

### Local testing without root/admin

To try it out without elevated privileges, remap every port above 1024:

```bash
HONEYPOT_IPS=127.0.0.1 \
DNS_PORT=15353 NTP_PORT=11230 SSDP_PORT=11900 CHARGEN_ADDR=127.0.0.1:11919 \
COORDINATOR_ADDR=127.0.0.1:8080 \
EVENTS_FILE=/tmp/honeypot_events.jsonl \
./honeypot
```

Then verify it's actually answering probes and recording them:

```bash
# coordinator/API is up
curl -s http://127.0.0.1:8080/metrics
# {"probe_counts":{"attacker":0,"noise":0,"scanner":0},"total":0,"ntp_probe_counts":{...}}

# send a raw DNS query for example.com and read the response - dig/nslookup don't reliably
# support custom ports across platforms, so a one-off Go client is the most portable option:
cat > /tmp/probe.go <<'EOF'
package main
import ("encoding/hex"; "fmt"; "net"; "time")
func main() {
	q, _ := hex.DecodeString("aaaa01000001000000000000076578616d706c6503636f6d0000010001")
	c, _ := net.Dial("udp", "127.0.0.1:15353")
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(q)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil { fmt.Println("no response:", err); return }
	fmt.Printf("got %d bytes: %s\n", n, hex.EncodeToString(buf[:n]))
}
EOF
go run /tmp/probe.go
# got 45 bytes: aaaa8400...  (1 A record - "minimal" mode amplification ~1.5x)

# metrics/events now reflect the probe
curl -s http://127.0.0.1:8080/metrics
# {"probe_counts":{"attacker":0,"noise":1,"scanner":0},"total":1,...}
curl -s http://127.0.0.1:8080/events
# {"events":[{"id":"...","source_ip":"127.0.0.1","queried_name":"example.com",
#   "query_type":"A","response_size_bytes":45,"probe_type":"noise", ...}],"total":1}
```

A minimal-mode DNS reply to an A query is ~45 bytes (1 A record); `probe_type` will read
`noise`/`scanner`/`attacker` depending on the classifier heuristics (see
[A/B Experiments](#ab-experiments)). The same event is appended as a JSON line to `EVENTS_FILE`
if set, or kept in memory only if it's empty.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HONEYPOT_IPS` | `127.0.0.1` | Comma-separated IPs to bind all protocol servers to |
| `DNS_PORT` | `53` | UDP port for the DNS servers |
| `NTP_PORT` | `123` | UDP port for the NTP servers |
| `SSDP_PORT` | `1900` | UDP port for the SSDP servers |
| `CHARGEN_ADDR` | `127.0.0.1:19` | Address for the CHARGEN server |
| `COORDINATOR_ADDR` | `0.0.0.0:8080` | HTTP API / dashboard address |
| `EVENTS_FILE` | *(empty)* | Path to a JSONL event log; falls back to in-memory storage when empty |
| `EXPERIMENTS_FILE` | *(empty)* | Path to a YAML file of experiments to load at startup (e.g. [experiments.yaml](experiments.yaml)) |

Binding to ports below 1024 (53, 123, 1900, 19) requires root/`sudo` (or an elevated terminal
on Windows), or `setcap`/port-forwarding if you want to run unprivileged - see
[Local testing without root/admin](#local-testing-without-rootadmin) above for a working
unprivileged example.

## Running with Docker

```bash
docker build -t honeypot .
docker run --rm -p 53:53/udp -p 123:123/udp -p 1900:1900/udp -p 19:19/udp -p 8080:8080 \
  -e HONEYPOT_IPS=0.0.0.0 honeypot
```

`compose.yml` defines a separate `loadgen` service (built from `Dockerfile.loadgen`) that runs
`scripts/spoof_monlist.py` against a target - used for spoofed-source amplification testing in
an isolated lab network. It requires `NET_ADMIN`/`NET_RAW` capabilities to send raw/spoofed
packets:

```bash
docker compose up --build
# or, per scripts/commands.txt, scale up multiple spoofing workers:
docker compose up --build --scale loadgen=10
```

## A/B Experiments

Experiments group one or more **variants**, each with its own per-protocol response config
(`dns_config`, `ntp_config`, `ssdp_config`) and a set of `assigned_ips`. Two assignment modes:

- `destination` - the honeypot IP a probe lands on determines the variant (sticky per IP, set at
  experiment creation)
- `source` - the variant is chosen per attacker source IP via a hash, sticky across repeated
  probes from the same source

Create, start, and stop experiments via the REST API (see below), or preload them at startup
with `EXPERIMENTS_FILE=experiments.yaml` - loading is idempotent, experiments with a matching
name are skipped on re-run. Only one experiment should be `active` (or have `auto_start: true`)
at a time; activating an experiment takes effect immediately, no restart required.

Response modes per protocol:

| Mode | DNS | NTP | SSDP |
|---|---|---|---|
| `minimal` | 1 A record (~45 B) | 0 peers | 0 services |
| `amplified` | 1 A + 9 TXT records (~1962 B, ~67x amplification) | N fake peers via mode-7 monlist | N fake services |

DNS also supports `realistic_ttl`, `realistic_padding` (SPF/DKIM-style TXT content instead of
`AAAA...` filler) and an explicit `response_ttl`/`response_size_bytes` override.

## REST API

| Method | Path | Description |
|---|---|---|
| `POST` | `/experiments` | Create an experiment with variants |
| `GET` | `/experiments` | List all experiments |
| `GET` | `/experiments/{id}` | Get experiment details (variants + assignments) |
| `POST` | `/experiments/{id}/start` | Activate an experiment |
| `POST` | `/experiments/{id}/stop` | Stop an experiment (falls back to default minimal config) |
| `GET` | `/metrics` | DNS + NTP probe counts by classification (`scanner`/`attacker`/`noise`) |
| `GET` | `/events` | Last 100 DNS events |
| `GET` | `/stats/timeseries` | Hourly probe counts over the last 24 hours |
| `GET` | `/stats/query-types` | DNS query type distribution |
| `GET` | `/stats/top-ips` | Top 10 source IPs by probe count |
| `GET` | `/dashboard` | HTML monitoring dashboard |

Example - create and start an experiment:

```bash
EXP=$(curl -s -X POST http://localhost:8080/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Response Size Study",
    "assignment_mode": "destination",
    "variants": [
      {"name": "Control",   "assigned_ips": ["127.0.0.1"], "dns_config": {"response_mode": "minimal",   "realistic_ttl": true}},
      {"name": "Treatment", "assigned_ips": ["127.0.0.2"], "dns_config": {"response_mode": "amplified", "realistic_ttl": false}}
    ]
  }')
ID=$(echo $EXP | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
curl -s -X POST http://localhost:8080/experiments/$ID/start
```

## Testing

```bash
go test ./...
# CI runs with race detection and verbose output:
go test ./... -race -v
```

Tests cover the rate limiter, DNS/NTP parsers, the classifier, in-memory repositories, the
experiment/variant-assignment use cases, the chargen/DNS/NTP domain services, and the
coordinator HTTP API. CI ([`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml)) runs the
same `-race -v` suite on Go 1.25 via a shared reusable workflow before any image is built/pushed.

## Manual / lab testing helpers

`scripts/` contains scapy-based tools used in [EXPERIMENT_GUIDE.md](EXPERIMENT_GUIDE.md) to
generate realistic and spoofed traffic against the honeypot in an isolated lab network:

- `ntpspoof.sh`, `sameipspoof.sh` - spawn many spoofed-source NTP requests (rate-limiter testing)
- `spoof_monlist.py`, `spoof_same_ip.py` - used by the `loadgen` Docker service
- `monlist.py`, `msearch.py`, `test_ntp_modes.py` - single-shot protocol probes
- `commands.txt` - example invocations

`cmd/multi_spoof_test/main.go` is a small standalone Go tool that binds multiple local source
IPs and fires concurrent NTP requests at a target, for load-testing without raw sockets.

`test_probe.sh` starts the built `honeypot` binary in the background, fires a single UDP probe
at port 53, and lets it run for 5 seconds - a quick smoke test.

## Safety & Ethics

This project intentionally implements UDP reflection/amplification behaviour (DNS, NTP, SSDP)
and ships scripts that spoof source IPs. That combination is also the recipe for a real DDoS
amplification attack. Only run this:

- on infrastructure you own or are explicitly authorized to test (isolated lab network, your
  own VMs/containers)
- never bound to a publicly routable interface unless it's a deliberately deployed, monitored
  research honeypot with legal sign-off
- never pointed at a third-party `--victim`/`--dst` you don't control - IP spoofing scripts in
  `scripts/` and the `loadgen` Compose service must only target hosts inside your lab
