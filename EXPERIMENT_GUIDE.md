# A/B Amplification Experiment Guide

This guide walks through building, running, and verifying a destination-based A/B experiment
that compares a minimal DNS response against an amplified one.

## What this tests

Two honeypot IPs serve the same DNS port. Each IP is bound to a different variant:

- **Control** (`127.0.0.1`) — returns a single A record (~45 bytes)
- **Treatment** (`127.0.0.2`) — returns an A record plus 9 large TXT records (~1962 bytes)

The amplification factor is `response_size / request_size`. A 29-byte query answered with
1962 bytes yields a **~67x amplification factor**. Recording this per-variant lets you compare
whether a larger response attracts more or different attacker behaviour over time.

## Prerequisites
- Go installed (`go version`)
- `curl` and `dig` available

## Step 1 - Build

```bash
cd honeypot
go build -o honeypot ./cmd/server
```

## Step 2 - Run the server

```bash
HONEYPOT_IPS="127.0.0.1,127.0.0.2" \
DNS_PORT=5354 \
EVENTS_FILE=/tmp/honeypot_events.jsonl \
./honeypot
```

Expected output:

```
[INFO] Honeypot application starting
[INFO] DNS events will be persisted to /tmp/honeypot_events.jsonl
```

Leave this terminal open. All subsequent steps run in a second terminal.

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `HONEYPOT_IPS` | `127.0.0.1` | Comma-separated IPs to bind DNS servers to |
| `DNS_PORT` | `5354` | UDP port all DNS servers listen on |
| `COORDINATOR_ADDR` | `0.0.0.0:8080` | HTTP API address |
| `EVENTS_FILE` | *(empty)* | Path to JSONL event log; in-memory when empty |

## Step 3 - Create the experiment

```bash
EXP=$(curl -s -X POST http://localhost:8080/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Response Size Study",
    "assignment_mode": "destination",
    "variants": [
      {
        "name": "Control",
        "assigned_ips": ["127.0.0.1"],
        "dns_config": {"response_mode": "minimal", "realistic_ttl": true}
      },
      {
        "name": "Treatment",
        "assigned_ips": ["127.0.0.2"],
        "dns_config": {"response_mode": "amplified", "realistic_ttl": false}
      }
    ]
  }')
echo $EXP | python3 -m json.tool
ID=$(echo $EXP | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Experiment ID: $ID"
```

`assignment_mode: destination` means each honeypot IP is permanently mapped to one variant.
The alternative is `source`, where the variant is assigned per source IP using a hash (sticky
across repeated queries from the same attacker).

## Step 4 - Activate the experiment

```bash
curl -s -X POST http://localhost:8080/experiments/$ID/start | python3 -m json.tool
```

The `status` field in the response must read `"active"`. From this point every DNS query
resolves its variant dynamically, no server restart required.

## Step 5 - Send queries and compare response sizes

Query the control IP:
```bash
dig @127.0.0.1 -p 5354 example.com A +noedns +notcp
```

Query the treatment IP:
```bash
dig @127.0.0.2 -p 5354 example.com A +noedns +notcp
```

Check the last line of each output:

```
;; MSG SIZE  rcvd: 45      ← control (minimal)
;; MSG SIZE  rcvd: 1962    ← treatment (amplified)
```

## Step 6 - Inspect the event log

```bash
cat /tmp/honeypot_events.jsonl
```

Expected output:

```
dst=127.0.0.1  size=45B    amp=1.6x   variant=86078133
dst=127.0.0.2  size=1962B  amp=67.7x  variant=bc445cf2
```

Both lines must have a non-empty variant prefix, confirming the active experiment was found
and the assignment resolved correctly.

## Step 7 - Stop the experiment

```bash
curl -s -X POST http://localhost:8080/experiments/$ID/stop | python3 -m json.tool
```

After stopping, both IPs fall back to the default minimal config (45 bytes) on the next query.
No restart needed.

## Response modes reference

| Mode | Records returned | Typical size | Amplification |
|---|---|---|---|
| `minimal` | 1 A record | ~45 B | ~1.5x |
| `amplified` | 1 A + 9 TXT (200 B each) | ~1962 B | ~67x |

## Testing the rate limiter

The token bucket allows a burst of 25 packets, then refills at 1 packet/second per source IP.
Send 50 queries in rapid succession from the same source:

```bash
for i in $(seq 1 50); do
  dig @127.0.0.2 -p 5354 example.com A +noedns +notcp +time=1 2>&1 | grep -E "MSG SIZE|timed out|no servers"
done
```

What to look for:

- Queries 1–25: `MSG SIZE rcvd: 1962` - the burst bucket is full, all packets answered
- Queries 26–50: the bucket is empty, the server drops the packet silently without sending a response

The server logs will show the accepted queries but nothing for the dropped ones: dropping is
intentional and silent. This confirms the real `IPAggregate` token bucket is wired in and the
`NoOpRateLimiter` (which allows everything) is not in use.

# Week 3 — DNS Configurable Responses, Multi-Protocol A/B Framework, and Scanner Classification

## Step 1 - Build

```bash
cd honeypot
go build -o honeypot ./cmd/server
```

## Step 2 - Run tests

```bash
go test ./...
```

Expected output:

```
ok  	github.com/Hacking-Lab-2026/honeypot/internal/adapters/api
ok  	github.com/Hacking-Lab-2026/honeypot/internal/usecases/dns
ok  	github.com/Hacking-Lab-2026/honeypot/internal/domain/services
ok  	github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment
```

All packages must pass with no failures before continuing.

## Step 3 - Run the server

Open two terminals. In terminal 1:

```bash
rm -f /tmp/honeypot_events.jsonl
HONEYPOT_IPS="127.0.0.1,127.0.0.2" \
DNS_PORT=5354 \
EVENTS_FILE=/tmp/honeypot_events.jsonl \
./honeypot
```

Expected output:

```
[INFO] Honeypot application starting
[INFO] DNS events will be persisted to /tmp/honeypot_events.jsonl
[INFO] Starting coordinator HTTP server on 0.0.0.0:8080
```

Leave terminal 1 running. Run all subsequent commands in terminal 2.

## Part 1 — Realistic Padding

Create an experiment with `realistic_padding: true` on the treatment variant and start it:

```bash
EXP=$(curl -s -X POST http://localhost:8080/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Realistic Padding Test",
    "assignment_mode": "destination",
    "variants": [
      {
        "name": "Control",
        "assigned_ips": ["127.0.0.1"],
        "dns_config": {"response_mode": "minimal", "realistic_ttl": true}
      },
      {
        "name": "Treatment",
        "assigned_ips": ["127.0.0.2"],
        "dns_config": {"response_mode": "amplified", "realistic_padding": true, "response_ttl": 300}
      }
    ]
  }')
ID=$(echo $EXP | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
curl -s -X POST http://localhost:8080/experiments/$ID/start | python3 -m json.tool
```

Query the treatment IP:

```bash
dig @127.0.0.2 -p 5354 example.com A +noedns +notcp
```

Expected: TXT records contain readable SPF/DKIM strings instead of `AAAA...`, and the final line still reads:

```
;; MSG SIZE  rcvd: 1962
```

## Part 2 — Multi-Protocol NTP Config

Create an experiment that sets both `dns_config` and `ntp_config` on each variant:

```bash
EXP=$(curl -s -X POST http://localhost:8080/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Multi-Protocol Test",
    "assignment_mode": "destination",
    "variants": [
      {
        "name": "Control",
        "assigned_ips": ["127.0.0.1"],
        "dns_config": {"response_mode": "minimal", "realistic_ttl": true},
        "ntp_config": {"response_mode": "minimal", "num_peers": 0}
      },
      {
        "name": "Treatment",
        "assigned_ips": ["127.0.0.2"],
        "dns_config": {"response_mode": "amplified", "realistic_padding": true},
        "ntp_config": {"response_mode": "amplified", "num_peers": 10}
      }
    ]
  }')
ID=$(echo $EXP | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
curl -s http://localhost:8080/experiments/$ID | python3 -m json.tool
```

Expected: each variant in the response contains both `dns_config` and `ntp_config` with all fields intact.

Test that invalid NTP config is rejected:

```bash
curl -s -X POST http://localhost:8080/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Invalid NTP Test",
    "assignment_mode": "destination",
    "variants": [
      {
        "name": "Bad",
        "assigned_ips": ["127.0.0.1"],
        "ntp_config": {"response_mode": "amplified", "num_peers": 0}
      },
      {
        "name": "Good",
        "assigned_ips": ["127.0.0.2"],
        "ntp_config": {"response_mode": "amplified", "num_peers": 10}
      }
    ]
  }' | python3 -m json.tool
```

Expected:

```json
{
    "error": "invalid experiment: variant \"Bad\" has NTP response mode \"amplified\" but NumPeers must be > 0"
}
```

## Part 3 — Scanner Classification and Metrics

Start the server with a fresh event log:

```bash
rm -f /tmp/honeypot_events.jsonl
HONEYPOT_IPS="127.0.0.1,127.0.0.2" \
DNS_PORT=5354 \
EVENTS_FILE=/tmp/honeypot_events.jsonl \
go run ./cmd/server/main.go
```

In a second terminal, trigger each classification:

```bash
# ANY query: "attacker"
dig @127.0.0.1 -p 5354 example.com ANY +noedns +notcp

# standard A query: "noise"
dig @127.0.0.1 -p 5354 example.com A +noedns +notcp

# 26 rapid queries: 26th and beyond are "attacker"
for i in $(seq 1 26); do
  dig @127.0.0.1 -p 5354 example.com A +noedns +notcp +time=1 > /dev/null 2>&1
done
dig @127.0.0.1 -p 5354 example.com A +noedns +notcp
```

Inspect the event log and confirm `probe_type` is set on every line:

```bash
cat /tmp/honeypot_events.jsonl | while read line; do echo $line | python3 -m json.tool; echo "---"; done
```

Check the metrics endpoint:

```bash
curl -s http://localhost:8080/metrics | python3 -m json.tool
```

Expected:

```json
{
    "probe_counts": {
        "attacker": 5,
        "noise": 24,
        "scanner": 0
    },
    "total": 29
}
```

`scanner` will be 0 in local testing. It increases as Shodan and Censys discover the honeypot in real deployment.