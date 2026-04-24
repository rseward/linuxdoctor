# linuxdoctor

Analyze performance metrics and recommend a course of action to resolve performance issues on Linux systems.

## Installation

```bash
pip install .
# or
uv sync
```

## Usage

### Analyze the current host (local)

```bash
linuxdoctor analyze
linuxdoctor analyze --json-output
linuxdoctor analyze --check cpu,memory,disk
linuxdoctor analyze --threshold strict
```

Gathers metrics from sar, vmstat, iostat, mpstat, and other standard Linux performance tools, then generates recommendations for improving system health.

### Analyze a remote node (via node_exporter)

```bash
linuxdoctor analyzenode <node-address>
linuxdoctor analyzenode server.example.com
linuxdoctor analyzenode server.example.com --port 9100 --threshold strict
linuxdoctor analyzenode server.example.com --json-output
linuxdoctor analyzenode server.example.com --no-recommendations
```

Connects to a Prometheus node_exporter endpoint on the remote host and analyzes CPU, memory, disk, disk I/O, network, and context switching metrics with threshold-based recommendations.

#### Counter-Aware Analysis (--resample)

Many node_exporter metrics are **cumulative counters** (monotonically increasing since boot):

- `node_cpu_seconds_total` — cumulative CPU time by mode
- `node_context_switches_total` — cumulative context switches since boot
- `node_disk_io_time_seconds_total` — cumulative disk I/O time

Reading these values directly produces **false positives** on long-running systems. For example, 500 million context switches is normal for a system that's been up 30 days — it means nothing without computing a rate.

Use `--resample` to take two samples and compute accurate rates:

```bash
# Take two samples 30 seconds apart (default)
linuxdoctor analyzenode server.example.com --resample

# Custom interval (60 seconds between samples)
linuxdoctor analyzenode server.example.com --resample --resample-interval 60
```

Without `--resample`, counter-based metrics show informational messages rather than potentially misleading warnings.

#### Registering Host Metadata (registerhost)

Context switch analysis is most accurate when normalized per CPU core. node_exporter exposes logical CPU count, but physical core count can differ (e.g., with hyperthreading). Register your host's actual core count for better accuracy:

```bash
# Register a host with its CPU core count
linuxdoctor registerhost server1 --cpu-cores 8
linuxdoctor registerhost 192.168.1.5 --cpu-cores 16 --cpu-sockets 2
linuxdoctor registerhost db-main --cpu-cores 32 -d "Production DB server"

# List registered hosts
linuxdoctor list-registered

# Remove a host
linuxdoctor unregisterhost server1
```

When context switch warnings are triggered without a registered core count, linuxdoctor will suggest using `registerhost` to improve accuracy.

Registry data is stored in `~/.config/linuxdoctor/hosts.yaml`.

### Analyzing Remote Nodes via SSH

For hosts that don't run node_exporter, you can collect metrics via SSH using traditional Linux performance tools (mpstat, vmstat, iostat, /proc). This requires:

- **Passwordless SSH access** — key-based authentication must be set up
- **Host keys accepted** — run `ssh user@host` once to accept the key
- **sysstat package** — `mpstat` and `iostat` should be available on the remote host

#### Registering an SSH Host

```bash
# Register a host for SSH metric collection
linuxdoctor registerhost remote1 --sshconnect admin@remote1 --cpu-cores 4
linuxdoctor registerhost remote2 --sshconnect remote2  # uses current username

# List registered hosts (shows collection method)
linuxdoctor list-registered
```

#### Analyzing an SSH Host

Once registered with `--sshconnect`, the `analyzenode` command automatically detects the SSH collection method:

```bash
# This will use SSH instead of node_exporter
linuxdoctor analyzenode remote1

# All regular options work
linuxdoctor analyzenode remote1 --json-output
linuxdoctor analyzenode remote1 --threshold strict
linuxdoctor analyzenode remote1 --resample
```

When run from the CLI, SSH connections allow interactive prompts (host key acceptance, passwords). From the web dashboard, `BatchMode=yes` is used — hosts requiring interactive auth are marked as unreachable.

#### Web Dashboard with SSH Hosts

```bash
linuxdoctor web
```

The dashboard shows SSH hosts with a **SSH** badge. Click any host for detailed analysis. SSH hosts that can't be reached (host key not accepted, password required) are shown as **unreachable** with guidance on how to fix the connection.

### List hosts from Prometheus

```bash
linuxdoctor list-hosts
linuxdoctor list-hosts prometheus.example.com
linuxdoctor list-hosts http://prometheus.example.com:9090
```

Discovers available hosts from a Prometheus server's targets API.

## CLI Commands

| Command | Description |
|---------|-------------|
| `analyze` | Analyze the current host using local performance tools |
| `analyzenode` | Analyze a remote node (node_exporter or SSH) |
| `list-hosts` | List available hosts from a Prometheus server |
| `registerhost` | Register host metadata (CPU cores, SSH connection) |
| `list-registered` | List all registered hosts and their metadata |
| `unregisterhost` | Remove a host from the registry |
| `web` | Start the web dashboard |

## Options

- `--json-output` / `-j` — Output results as JSON
- `--no-recommendations` — Skip recommendation generation
- `--check` / `-c` — Run only specific checks (cpu, memory, disk, io, network, load, sar)
- `--threshold` / `-t` — Threshold profile: default, strict, or relaxed
- `--verbose` / `-v` — Show verbose output (analyzenode)
- `--port` / `-p` — Node exporter port (default: 9100, analyzenode only)
- `--resample` — Take two samples to compute rates for counter metrics (analyzenode only)
- `--resample-interval` — Seconds between resamples (default: 30, requires --resample)

## Threshold Profiles

Three built-in threshold profiles are available:

### Context Switch Thresholds (per-core, rate-based)

| Level | Default | Strict | Relaxed |
|-------|---------|--------|---------|
| Warning (per core/sec) | 1,000 | 500 | 2,000 |
| Critical (per core/sec) | 5,000 | 2,000 | 10,000 |
| Warning (absolute/sec, no cores) | 10,000 | 5,000 | 20,000 |

### I/O Wait Thresholds (% of CPU time)

| Level | Default | Strict | Relaxed |
|-------|---------|--------|---------|
| Warning | 20% | 10% | 40% |

### Disk I/O Utilization Thresholds (% busy, rate-based)

| Level | Default | Strict | Relaxed |
|-------|---------|--------|---------|
| Warning | 70% | 50% | 85% |
| Critical | 90% | 70% | 95% |

## Project Structure

```
src/linuxdoctor/
├── __init__.py          # Package init with re-exports
├── cli.py               # Click CLI entry point
├── analyze.py            # Local host analysis (sar, vmstat, etc.)
├── analyzenode.py        # Remote node analysis (node_exporter & SSH)
│                        #   Counter-aware: uses rate() for counters, not raw values
│                        #   Supports --resample for two-sample rate computation
│                        #   SSH mode: collects via traditional perf tools over SSH
├── collectors.py         # Local metric collectors
├── host_registry.py      # Host metadata registry (CPU cores, SSH connections)
├── ssh_collector.py      # SSH metric collection (mpstat, vmstat, iostat, etc.)
├── web.py                # Web dashboard (node_exporter + SSH hosts)
├── recommendations.py    # Local recommendation engine
├── prometheus.py         # Prometheus host discovery
└── node_analyzer.py      # Re-export of analyzenode for compatibility
```

## Counter-Aware Design

linuxdoctor's remote analysis (`analyzenode`) is designed to avoid the common pitfall of comparing cumulative counter values to static thresholds. Key principles:

1. **Never compare raw counter values to thresholds.** Counters like `node_context_switches_total` accumulate since boot — a value of 500M is normal for a 30-day-old system.

2. **Compute rates from two samples.** The `--resample` flag takes two samples spaced `--resample-interval` seconds apart (default 30s) and computes the per-second rate.

3. **Use percentage-of-total for CPU metrics.** Since `node_cpu_seconds_total` has labels for each mode (idle, iowait, system, etc.), dividing iowait by total gives a valid percentage regardless of system uptime.

4. **Normalize by CPU core count.** Context switch rates are meaningless without knowing the number of CPU cores. 10,000 switches/sec might be fine on a 64-core system but terrible on a single-core VM. Use `registerhost` to provide core counts for accurate analysis.

5. **Handle counter resets gracefully.** If the second sample is lower than the first (system rebooted between samples), linuxdoctor uses the current value as a new baseline rather than producing a misleading negative rate.

## Requirements

- Linux system with standard performance tools for local analysis: `sar` (sysstat), `vmstat`, `iostat`, `mpstat`, `free`, `df`, `perf`, `uptime`
- Remote node analysis (node_exporter mode): a running `node_exporter` on the target host
- Remote node analysis (SSH mode): `ssh` client, passwordless key-based auth, and `sysstat` package on the remote host
- `list-hosts` requires access to a Prometheus server API
- Python 3.9+

## License

MIT