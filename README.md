# NetScan

**Professional network host discovery and authorised load testing for the terminal.**

NetScan is an asynchronous network scanner that combines ICMP, TCP and ARP
discovery in one fast, dependency-light tool. It is built for people who spend
their day in a shell: clear output, honest progress, useful summaries, and
machine-readable exports when you need them.

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  » NETSCAN  network host discovery                                   v2.2.0  │
│  async ICMP · TCP · ARP discovery                                            │
╰──────────────────────────────────────────────────────────────────────────────╯

      targets  192.168.1.0/24   254 addresses
        ports  48 ports selected   curated common set
      timeout  1 s
  concurrency  256 probes in flight
      methods  ICMP · TCP
    intensity  Normal  probe pacing
      lookups  on  reverse DNS

live hosts   4
IP             HOSTNAME    MAC                   RTT   METHOD       PORTS
────────────────────────────────────────────────────────────────────────────
192.168.1.1    router      a4:2b:8c:11:22:33   0.5 ms   ICMP · TCP   53,80 +1
192.168.1.10   workstation b8:27:eb:44:55:66   1.2 ms   ICMP          —
192.168.1.24   nas         00:11:32:aa:bb:cc   0.8 ms   ICMP · TCP   22,443,5000
192.168.1.31   printer     3c:2a:f4:12:34:56   4.7 ms   TCP          80,9100

╭─ scan complete ──────────────────────────────────────────────────────────────╮
│      hosts online  4                       duration  3.41s                   │
│  addresses probed  254                   throughput  1.2 hosts/s             │
│          found by  ICMP 3 · TCP 3      probe errors  0                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

The table adapts to the terminal width: on narrow consoles it drops optional
columns rather than truncating every value into an ellipsis.

---

## Highlights

- **Three discovery methods** — ICMP echo, TCP handshake and the local ARP
  table. Combine them or use one.
- **Genuinely asynchronous** — one event loop, a global probe semaphore and
  batched port probes. A /24 finishes in seconds on a healthy LAN.
- **No administrator rights required** — ICMP uses the platform `ping` binary
  instead of raw sockets, so it runs as a normal user on Windows, macOS and
  Linux.
- **Port states, not just "open"** — every probe is classified as `open`,
  `closed`, `filtered` or `error`, so a silent firewall is visible instead of
  being silently folded into "closed".
- **Service and banner detection** — `--services` reads service banners and
  `--tls-info` extracts certificate metadata when the optional `cryptography`
  extra is installed.
- **Pacing controls** — `--intensity polite|normal|aggressive`, a global
  `--rate` ceiling and a per-host `--host-delay` keep scans considerate on
  fragile networks.
- **Scope enforcement** — an allowlist (`--scope-file`) and denylist
  (`--exclude`) are enforced before a single packet is sent, and public targets
  trigger an explicit warning.
- **Responsive console UI** — Rich panels, a live progress bar, colour-coded
  latency and a summary that tells you what actually happened.
- **Self-contained HTML reports** — one file with inline CSS and SVG, no
  scripts and no external requests, ready to attach to a ticket or build
  artefact.
- **Watch mode** — rescan on an interval and report hosts that join or leave.
- **Report diffing and history** — `netscan diff` compares two JSON reports;
  `netscan history` lists runs stored in a local SQLite database.
- **Repeatable configuration** — a `netscan.toml` file with named profiles, where
  explicit command-line flags always win.
- **Authorised load testing** — a bounded, single-origin `stress` command for
  TCP, HTTP and UDP, with a live dashboard, latency percentiles, SLO gates, an
  audit trail and hard safety caps.
- **Automation friendly** — JSON, CSV, HTML and plain-text export, quiet mode and
  meaningful exit codes.
- **Typed, testable engine** — the scanner has no UI dependency; the CLI and the
  Rich front-end are thin layers on top.

---

## Requirements

- Python **3.10+**
- [`rich`](https://github.com/Textualize/rich) for the console interface
- Optional: `psutil` for exact local netmask detection (otherwise a `/24` is
  assumed for automatic targets)
- Optional: `cryptography` for `--tls-info` certificate metadata

## Install

```bash
git clone <this-repo>
cd NetworkHostScanner

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Use it directly:

```bash
python scanner.py --help
python scanner.py 192.168.1.0/24
```

Or install the `netscan` command:

```bash
pip install -e .
netscan 192.168.1.0/24
```

With the optional extras:

```bash
pip install -e ".[tls]"   # certificate metadata for --tls-info
pip install -e ".[dev]"   # test, lint, type-check and audit tooling
```

`python -m netscan` works too.

---

## Quick start

```bash
# Scan the local network (auto-detected, usually a /24)
python scanner.py

# Scan a subnet
python scanner.py 192.168.1.0/24

# Probe selected services
python scanner.py 10.0.0.5 -p 22,80,443

# Scan an address range with a longer wait time
python scanner.py 192.168.1.10-50 --timeout 2

# Include layer-2 neighbours from the ARP table
python scanner.py 192.168.1.0/24 -m arp

# Faster discovery only: ICMP, no port probes, no reverse DNS
python scanner.py 192.168.1.0/24 -m ping --no-dns

# Gentle pacing and banner detection
python scanner.py 192.168.1.0/24 --intensity polite --services

# Enforce an allowlist and denylist
python scanner.py 10.0.0.0/24 --scope-file scope.txt --exclude 10.0.0.1

# Export a standalone HTML report
python scanner.py 192.168.1.0/24 -o scan.html

# Compare two reports
python scanner.py diff old.json new.json

# Watch the network and report joins/leaves
python scanner.py 192.168.1.0/24 -w 30

# Authorised load test against a service you own (see the section below)
python scanner.py stress 127.0.0.1:8080 --authorize
```

---

## Command-line reference

### Targets

| Form | Example |
|------|---------|
| Single address | `192.168.1.42` |
| CIDR network (network and broadcast are skipped) | `192.168.1.0/24` |
| IPv4 range | `192.168.1.10-50` or `192.168.1.10-192.168.1.50` |
| Hostname | `router.lan` |
| Automatic local network | no target, or `auto` |
| Multiple targets | `192.168.1.0/24 10.0.0.0/24` |

Targets can be positional or passed with `-t/--target`; the two forms combine.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --ports SPEC` | `top`, `all`, `1-1024`, `22,80,443`, `ssh,http` | `top` |
| `--timeout SECONDS` | Wait time per probe | from `--intensity` |
| `-c, --concurrency N` | Maximum probes in flight | from `--intensity` |
| `--intensity LEVEL` | `polite`, `normal` or `aggressive` pacing preset | `normal` |
| `--rate N` | Global probe ceiling per second | unlimited |
| `--host-delay SECONDS` | Minimum gap between host batches | from `--intensity` |
| `-m, --method` | `ping`, `tcp`, `arp`; repeat to combine | `ping tcp` |
| `--no-dns` | Skip reverse DNS lookups | off |
| `--services` | Read service banners on open ports | off |
| `--tls-info` | Extract TLS certificate metadata (needs `cryptography`) | off |
| `--scope-file PATH` | Allowlist of targets (CIDR, range, address, comments) | — |
| `--exclude SPEC` | Denylist entry; repeat or comma-separate | — |
| `-f, --format` | `table`, `compact`, `json`, `csv`, `txt`, `html` | inferred |
| `-o, --output PATH` | Write a report to a file | — |
| `--db PATH` | Append the run to a SQLite history database | — |
| `-q, --quiet` | No banner, progress or summary | off |
| `-w, --watch [SECONDS]` | Rescan continuously and diff results | `10` |
| `--config PATH` | TOML configuration file | `netscan.toml` if present |
| `--profile NAME` | Named profile from the config file | — |
| `--no-color` | Disable ANSI colours | off |
| `--debug` | Show tracebacks on errors | off |
| `--version` | Print the version | — |

`-s/--scanner` and `-v/--verbose` are accepted for compatibility with the 1.x
command line.

### Intensity presets

| Preset | Timeout | Concurrency | Batch delay |
|--------|---------|-------------|-------------|
| `polite` | 2.0 s | 32 | 50 ms |
| `normal` | 1.0 s | 256 | 0 ms |
| `aggressive` | 0.5 s | 1024 | 0 ms |

Explicit `--timeout` and `--concurrency` values override the preset. Use
`polite` on shared or production networks, and `aggressive` only on lab
equipment you control.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed |
| `1` | Scan failed (see the error panel) |
| `2` | Invalid usage, target, scope or configuration |
| `130` | Interrupted with Ctrl+C |

---

## Output formats

### Table (default)

Designed for humans. Columns collapse gracefully on narrower terminals. Port
state is shown as a chip when it is not simply open.

### Compact

One line per host, ideal for logs:

```bash
python scanner.py 192.168.1.0/24 -f compact
```

```
192.168.1.1     router                    a4:2b:8c:11:22:33  ICMP+TCP   53, 80, 443
192.168.1.10    workstation               b8:27:eb:44:55:66  ICMP
```

### JSON

```bash
python scanner.py 192.168.1.0/24 -f json -o scan.json
```

```json
{
  "tool": "NetScan",
  "version": "2.2.0",
  "started_at": "2026-11-11T12:00:00",
  "finished_at": "2026-11-11T12:00:03",
  "duration_s": 3.412,
  "targets": ["192.168.1.0/24"],
  "summary": {
    "hosts_online": 4,
    "addresses_probed": 254,
    "probe_errors": 0,
    "by_method": { "ping": 3, "tcp": 3, "arp": 1 },
    "port_states": { "open": 12, "closed": 40, "filtered": 8 },
    "services": 6
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router",
      "mac": "a4:2b:8c:11:22:33",
      "latency_ms": 0.5,
      "methods": ["ping", "tcp"],
      "open_ports": [53, 80, 443],
      "ports": [
        {"port": 80, "state": "open", "latency_ms": 0.4, "service": null}
      ],
      "services": [
        {
          "port": 80,
          "banner": "HTTP/1.1 200 OK",
          "server": "nginx/1.27",
          "tls": false,
          "tls_subject": null,
          "tls_issuer": null,
          "tls_expires": null,
          "tls_days_left": null
        }
      ]
    }
  ]
}
```

Writing JSON or CSV to stdout implies quiet mode, so the output is safe to pipe:

```bash
python scanner.py 10.0.0.0/24 -f json > scan.json
```

### CSV / text

```bash
python scanner.py 10.0.0.0/24 -f csv -o scan.csv
python scanner.py 10.0.0.0/24 -o scan.txt
```

### HTML

```bash
python scanner.py 192.168.1.0/24 -o scan.html
python scanner.py stress 127.0.0.1:8080 --authorize -o load.html
```

HTML reports must be written to a file. They are completely self-contained:
inline CSS, inline SVG charts, no JavaScript and no network requests, so they
render the same offline, in an email attachment or in a build artefact. The
layout adapts to narrow screens and follows the system light/dark preference.

---

## Scope and pacing

`--scope-file` takes a plain-text allowlist. Blank lines and `#` comments are
ignored; CIDR blocks, single addresses, IPv4 ranges and hostnames are accepted:

```
# authorised lab range
192.168.10.0/24
10.20.0.5
10.20.0.10-40
```

`--exclude` is a denylist applied after the allowlist. It can be repeated or
given as a comma-separated list:

```bash
netscan 192.168.10.0/24 --scope-file scope.txt --exclude 192.168.10.1,192.168.10.2
```

Both lists are enforced before scanning starts: a target that falls outside the
allowlist, or inside the denylist, is refused with exit code `2`. If the final
target set contains public addresses, NetScan prints a warning reminding you to
scan only systems you own or have written permission to test.

Pacing is independent of scope. `--intensity polite` is the safe choice for a
busy network; `--rate` and `--host-delay` add further control:

```bash
# At most 200 probes per second, with 100 ms between host batches
netscan 10.0.0.0/24 --intensity polite --rate 200 --host-delay 0.1
```

---

## Configuration files

NetScan reads `netscan.toml` from the working directory automatically. Use
`--config` to point somewhere else and `--profile` to select a named profile.
Explicit command-line flags always take precedence over file values.

```toml
[scan]
ports = "top"
intensity = "polite"
services = true
exclude = ["192.168.1.1"]

[stress]
duration = 30
rate = 200

[profiles.lab.scan]
ports = "1-1024"
timeout = 0.5

[profiles.lab.stress]
duration = 60
rate = 500
keep_alive = true
headers = ["Accept: application/json"]
```

```bash
netscan --profile lab 192.168.10.0/24
netscan stress --profile lab http://10.0.0.5:8080 --authorize
```

Unknown keys and wrong value types are reported as configuration errors rather
than being silently ignored.

---

## Report diffing

`netscan diff` compares two discovery reports produced with `-f json`. It shows
hosts that appeared, disappeared or changed, including port and service
changes:

```bash
netscan 192.168.1.0/24 -f json -o before.json
netscan 192.168.1.0/24 -f json -o after.json
netscan diff before.json after.json
```

```
REPORT DIFF  192.168.1.0/24                              +1  -1  ~1  =12

  +  192.168.1.44   added     open ports 22, 443
  -  192.168.1.31   removed   open ports 80, 9100
  ~  192.168.1.1    changed   opened 8443, service 80:nginx → 80:caddy

1 added · 1 removed · 1 changed · 12 unchanged
```

`--json` emits a machine-readable diff for CI. Load-test reports are rejected
because they describe a different kind of measurement.

---

## Run history

Pass `--db PATH` to a scan or load test to append the run to a local SQLite
database. The full JSON payload is stored alongside indexed summary columns, so
history remains queryable as report formats evolve.

```bash
netscan 192.168.1.0/24 --db runs.db
netscan stress 127.0.0.1:8080 --authorize --db runs.db
netscan history --db runs.db
```

```
ID | KIND   | STARTED             | TARGET            |   COUNT |      DETAIL
---+--------+---------------------+-------------------+---------+-------------
 2 | stress | 2026-11-11 11:16:43 | tcp://127.0.0.1:1 |  5 reqs | 0 responses
 1 | scan   | 2026-11-11 11:16:43 | 127.0.0.1         | 1 hosts |    1 probed
```

`--kind scan|stress`, `--limit N` and `--json` narrow the listing.

---

## Watch mode

```bash
python scanner.py 192.168.1.0/24 -w 30
```

The first cycle prints the full table. Later cycles report only changes:

```
  + 192.168.1.44   laptop        joined
  - 192.168.1.31   printer       left

  cycle 4  ·  4 online  ·  +1 / -1  ·  3.2s  ·  next in 30s
```

Combine with `-o` to keep the latest snapshot on disk after every cycle.

---

## Authorised load testing

`netscan stress` generates **bounded, single-origin traffic** against a service
you own or are contracted to test. It is a load generator, not a botnet: one
process on one host, no address spoofing, no reflection and no amplification.

> **Authorization is not optional.** Unauthorised load testing is illegal in most
> jurisdictions and can take a production service offline. The command refuses
> to run without `--authorize`, and public addresses additionally require
> `--allow-public`. See [docs/AUTHORIZED_USE.md](docs/AUTHORIZED_USE.md).

### What it measures

| Pattern | Traffic per attempt | Counted as a response |
|---------|---------------------|-----------------------|
| `tcp` | TCP handshake, then close | handshake completed |
| `http` | one HTTP request, optionally on a reused connection | status line and headers received |
| `udp` | one datagram, fire-and-forget | datagram handed to the kernel |

`http://` and `https://` targets select HTTP automatically; everything else
defaults to TCP. The report includes attempts, responses, transport failures,
timeouts, HTTP 4xx/5xx counts, payload bytes and latency
min/mean/p50/p90/p99/max.

### Quick start

```bash
# 30-second HTTP test, 50 workers, 200 requests/second cap
python scanner.py stress https://staging.example.com/health \
    --authorize --duration 30 --concurrency 50 --rate 200

# TCP connect test against a local port
python scanner.py stress 127.0.0.1:8080 --authorize

# Paced UDP test: 2,000 datagrams per second, 64 bytes each
python scanner.py stress 10.0.0.5:53 -m udp --authorize -r 2000

# Warmed-up, ramped run gated on SLOs, with an audit trail
python scanner.py stress http://10.0.0.5:8080/api --authorize \
    --warmup 10 --ramp 20 --slo-success 99.5 --slo-p99 250 \
    --operator alice --authorization-ref CHG-1234

# Realistic HTTP: headers, basic auth, expectations and keep-alive
python scanner.py stress http://127.0.0.1:8000 --authorize \
    --keep-alive --header "Accept: application/json" \
    --basic-auth user:secret --expect-status 200 --expect-body '"ok"'

# CI-friendly: no prompt, JSON on stdout
python scanner.py stress http://10.0.0.20/ --authorize --yes -f json > load.json
```

### Safety model

The guardrails are part of the feature, not an afterthought:

- `--authorize` is mandatory; there is no code path that starts traffic without
  the acknowledgement.
- Loopback, private and link-local targets work by default. Public addresses
  need `--allow-public` as a second, deliberate opt-in.
- Multicast, broadcast, reserved and unspecified addresses are always refused.
- Hard caps: **600 s**, **512 workers**, **50,000 requests/s** and **1,400-byte**
  datagrams.
- Conservative defaults: 10 s, 25 workers, 100 requests/s.
- HTTP redirects are followed only within the same origin (scheme, host and
  port), up to three hops.
- Unless `--yes` is passed, an interactive prompt asks the operator to type
  `yes`; non-interactive shells must opt in explicitly.
- `Ctrl+C` stops immediately and reports the partial result instead of losing it.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `TARGET` | `host`, `host:port`, `http(s)://host/path` or `[ipv6]:port` | — |
| `-m, --method` | `tcp`, `http`, `udp` | inferred |
| `-p, --port` | override the port taken from the target | from target |
| `-d, --duration` | measured test length in seconds (max 600) | `10` |
| `-c, --concurrency` | parallel workers / in-flight ceiling (max 512) | `25` |
| `-r, --rate` | global request cap per second; `0` = worker-bound | `100` |
| `--timeout` | per-request timeout (max 30 s) | `2` |
| `--warmup SECONDS` | traffic before measurement; excluded from statistics | `0` |
| `--ramp SECONDS` | linearly ramp the offered rate over this window | `0` |
| `--path` | override the HTTP request path | from target, else `/` |
| `--http-method` | HTTP verb | `GET` |
| `--header 'NAME: VALUE'` | add a request header; repeatable | — |
| `--basic-auth USER:PASS` | send HTTP basic authentication | — |
| `--expect-status CODE[,CODE]` | treat other status codes as failures | any |
| `--expect-body TEXT` | require this text in the response body | — |
| `--keep-alive` | reuse HTTP/1.1 connections | off |
| `--follow-redirects` | follow up to 3 same-origin redirects | off |
| `--slo-success PCT` | minimum success rate | — |
| `--slo-error PCT` | maximum error rate | — |
| `--slo-timeout PCT` | maximum timeout rate | — |
| `--slo-p99 MS` | maximum p99 latency | — |
| `--operator NAME` | who ran the test | — |
| `--authorization-ref REF` | ticket, change or contract reference | — |
| `--note TEXT` | free-form note stored with the report | — |
| `--payload-bytes` | UDP datagram size (max 1,400) | `64` |
| `--tls` / `--no-tls` | force TLS on or off | from scheme |
| `--insecure` | skip certificate verification | off |
| `--authorize` | confirm authorization (required) | — |
| `--allow-public` | permit public addresses | off |
| `-y, --yes` | skip the interactive confirmation | off |
| `-f, --format` | `table`, `json`, `csv`, `html` | inferred |
| `-o, --output` | write a JSON, CSV or HTML report | — |
| `--db PATH` | append the run to a SQLite history database | — |
| `-q, --quiet` | no banner, dashboard or summary | off |

### Warmup, ramp and open-loop scheduling

When `--rate` is set, NetScan dispatches requests on a fixed schedule instead of
letting workers run as fast as they can. That is an **open-loop** load test: if
every worker is busy, the schedule slot is *dropped* and counted, rather than
silently lowering the offered rate. The report includes dropped schedules and
scheduler lag p99, so an overloaded generator is visible instead of flattering
the target.

`--warmup` runs traffic before measurement starts; those requests are discarded
from every statistic. `--ramp` applies a linear ramp to the measured window, so
you can start gently and reach the target rate without a cold-start spike.

### Service-level objectives

Any combination of SLOs can gate the run:

```bash
netscan stress http://10.0.0.5/ --authorize \
    --slo-success 99.5 --slo-error 0.5 --slo-timeout 0.1 --slo-p99 250
```

Rates accept either a percentage (`99.5`) or a fraction (`0.995`). Results are
printed in the summary and stored in JSON/HTML. The command exits `3` when a
threshold is breached, which is distinct from `1` (the target answered nothing)
and `2` (usage or safety error), so CI can tell a performance regression from a
broken test.

### Reading the result

```
╭─ test complete ──────────────────────────────────────────────────────────────╮
│  Service stayed responsive at 196 req/s.                                     │
│                                                                              │
│      attempts  5,884                responses  5,884                         │
│      failures  0                 success rate  100.0%                        │
│    throughput  196 req/s             duration  30.02s                        │
│  payload sent  603.1 KiB     payload received  4.8 MiB                       │
│                                                                              │
│  min          mean         p50         p90         p99         max           │
│  2.1 ms       8.4 ms       7.9 ms      14.2 ms     28.6 ms     41.0 ms       │
│                                                                              │
│  SLOs  all passed                                                            │
│    ✓ success rate  100.00%  ≥ 99.50%                                         │
│    ✓ p99 latency   28.6 ms  ≤ 250 ms                                         │
│                                                                              │
│  status  200 5,884                                                           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

- **Responses** are completed requests. **Failures** are transport errors
  (refused, reset, unreachable, TLS, timeout) plus any expectation mismatch
  configured with `--expect-status` or `--expect-body`.
- An HTTP 4xx/5xx is still a completed response: it counts in `responses` and is
  reported separately as an HTTP error.
- Latency percentiles describe successful requests; timeouts are counted
  separately instead of inflating p99. Percentiles are exact up to 50,000
  samples and estimated from a uniform reservoir beyond that, so long
  high-rate runs stay memory-bounded.
- The command exits `1` when zero requests succeeded, which lets CI catch an
  unreachable or misconfigured target. It exits `3` when SLOs are breached.

### Exports

```bash
python scanner.py stress http://10.0.0.20/ --authorize --yes -f json -o load.json
python scanner.py stress http://10.0.0.20/ --authorize --yes -f csv  -o load.csv
python scanner.py stress http://10.0.0.20/ --authorize --yes -o load.html
```

JSON contains the full summary, latency block, error counts, status codes, SLO
results, audit metadata, scheduler statistics and a periodic timeline (two
samples per second for short runs, one per second otherwise). CSV is the
timeline only, which is what spreadsheets and graphing tools want. HTML is a
self-contained report with an inline throughput chart.

### Python API

```python
import asyncio

from netscan import SloThresholds, StressConfig, StressMethod, StressTester

config = StressConfig(
    target="http://10.0.0.20:8080/health",
    method=StressMethod.HTTP,
    duration=10.0,
    concurrency=20,
    rate=100.0,
    warmup=2.0,
    keep_alive=True,
    slo=SloThresholds(min_success_rate=0.99, max_p99_ms=250),
    authorized=True,
)

report = asyncio.run(StressTester(config).run())
print(f"{report.throughput:.0f} req/s  p99={report.latency_p99_ms:.1f} ms")
print("SLOs passed" if report.slo_ok else "SLO breach")
```

A custom reporter implements the same three callbacks the dashboard uses:

```python
class Reporter:
    def on_start(self, plan) -> None: ...
    def on_tick(self, snapshot) -> None: ...
    def on_finish(self, report) -> None: ...
```

### Why single-origin

A real distributed denial-of-service needs thousands of compromised hosts and is
illegal to operate. This command deliberately cannot produce one. If you need
distributed load, use a managed load-testing service or a coordinated cluster you
control, with the same authorization discipline.

---

## Python API

The engine is independent of the CLI and has no Rich dependency.

```python
import asyncio

from netscan import DiscoveryMethod, NetworkScanner, ScanConfig

config = ScanConfig(
    targets=("192.168.1.0/24",),
    ports=(22, 80, 443),
    timeout=1.0,
    concurrency=128,
    methods=frozenset({DiscoveryMethod.PING, DiscoveryMethod.TCP}),
    services=True,
)

report = asyncio.run(NetworkScanner(config).scan())

for host in report.hosts:
    ports = ", ".join(str(port) for port in host.open_ports) or "-"
    print(f"{host.ip:<15} {host.hostname or '-':<24} {ports}")
```

Every host also exposes `port_details` (one `PortResult` per probe, including
`state`, `latency_ms` and optional `ServiceInfo`) and `services`.

Custom progress reporting is a small protocol:

```python
class Reporter:
    def on_start(self, total: int) -> None: ...
    def on_host(self, ip: str) -> None: ...
    def on_progress(self, done: int, total: int, found: int) -> None: ...
    def on_finish(self) -> None: ...


report = asyncio.run(NetworkScanner(config).scan(Reporter()))
```

---

## How it works

```
netscan/
├── cli.py           argparse front-end, exit codes, watch loop
├── engine.py        async orchestrator and probe budgeting
├── scanners.py      ICMP, TCP, banner/TLS and reverse-DNS primitives
├── arp.py           cross-platform neighbour table reader
├── targets.py       CIDR / range / hostname expansion and scope checks
├── ports.py         port and service-name parsing
├── models.py        Host, PortResult, ServiceInfo and report value objects
├── rate.py          shared token-bucket rate limiter
├── exporters.py     JSON, CSV, text and HTML serialisation
├── report_html.py   self-contained HTML reports
├── config.py        TOML configuration and profile merging
├── diff.py          report comparison model
├── diff_cli.py      `netscan diff` front-end
├── history.py       SQLite run history
├── history_cli.py   `netscan history` front-end
├── stress.py        bounded load-test engine and safety gates
├── stress_cli.py    `netscan stress` front-end
├── stress_ui.py     live load-test dashboard and summary
├── streams.py       UTF-8 stdout/stderr handling
├── ui.py            Rich console presentation
├── constants.py     curated ports and limits
└── __main__.py      `python -m netscan`
```

A scan runs in five stages:

1. **Expand targets** — CIDR, ranges and hostnames become a deduplicated list of
   addresses, capped at 65,536 entries. Scope and exclude files are enforced
   here.
2. **Prime the ARP table** — only when `arp` is an explicit discovery method.
3. **Probe concurrently** — ICMP and TCP run in parallel per host. Port probes
   are issued in batches and gated by one global semaphore plus the optional
   rate limiter, so concurrency is predictable regardless of target count.
4. **Enrich** — the neighbour table is read again to attach MAC addresses,
   reverse DNS fills in hostnames, and optional service/TLS probes collect
   banners.
5. **Report** — results are sorted numerically, rendered, and optionally
   exported or recorded in history.

No raw sockets, no packet injection, no privileged helper: every probe is a
normal user-land operation.

---

## Important notes

- **TCP "open" means the handshake completed.** Ports that silently drop
  packets are reported as `filtered` when the probe times out, but a host
  firewall can make `filtered` and `closed` hard to distinguish; both cost the
  full `--timeout`.
- **ARP only works on the local layer-2 segment.** Entries can be stale, so
  `-m arp` may occasionally report a neighbour that just went offline. ARP is
  best used to *supplement* ICMP/TCP, not replace it.
- **IPv6 is supported for ICMP and TCP.** ARP is IPv4-only.
- **Automatic target detection** uses a UDP route lookup and prefers the actual
  netmask when `psutil` is installed; otherwise it assumes a `/24`.
- **Performance is dominated by filtered ports.** Scanning 48 ports on 254
  hosts is ~12,000 probes; at 256 concurrent probes a fully filtered network
  can take around a minute. Use `-m ping` for fast discovery-only sweeps and
  `--intensity polite` on networks you share.
- **Only scan networks you own or are explicitly authorised to test.**
- **Only run `netscan stress` against systems you own or have written permission
  to test.** The command enforces an authorization acknowledgement and a
  private-address default, but responsibility for lawful use is yours.

---

## Troubleshooting

| Symptom | What to try |
|---------|-------------|
| No hosts found | Try `-m tcp`, `-m arp` or a wider `-p` list; some hosts block ICMP |
| Scan feels slow | Add `--no-dns`, reduce `--ports`, lower `--timeout` |
| Missing MAC addresses | The host is on another subnet, or the neighbour entry expired |
| Hostnames are missing | Reverse DNS is not configured on the network; use `--no-dns` to skip |
| `--tls-info` does nothing | Install the optional extra: `pip install -e ".[tls]"` |
| A target is refused | Check `--scope-file` / `--exclude`; scope is enforced before probing |
| Garbled box characters | Use Windows Terminal / a UTF-8 capable terminal; NetScan forces UTF-8 output |
| A scan fails immediately | Re-run with `--debug` for the full traceback |
| Stress exits `3` | An SLO threshold was breached; inspect the summary or JSON report |

---

## Development

```bash
pip install -e ".[dev]"

python -m unittest discover -s tests -t . -v
python -m ruff check .
mypy netscan
coverage run -m unittest discover -s tests -t . && coverage report
python -m pip_audit -r requirements.txt
```

The test suite covers target expansion and scope enforcement, port parsing,
ARP output formats, report serialisation, HTML escaping and self-containment,
TOML profile merging, report diffing, SQLite history and the load-test engine.
Load-test engine tests bind loopback servers inside the test process, so the
suite never sends traffic to a third party.

Continuous integration runs the same checks on Python 3.10 through 3.13. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and
[docs/AUTHORIZED_USE.md](docs/AUTHORIZED_USE.md) for the acceptable-use policy.

---

## License

MIT — see [LICENSE](LICENSE).
