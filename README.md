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

### List hosts from Prometheus

```bash
linuxdoctor list-hosts
linuxdoctor list-hosts prometheus.example.com
linuxdoctor list-hosts http://prometheus.example.com:9090
```

Discovers available hosts from a Prometheus server's targets API.

## CLI Commands

- `analyze` — Analyze the current host using local performance tools
- `analyzenode` — Analyze a remote node using node_exporter metrics
- `list-hosts` — List available hosts from a Prometheus server

## Options

- `--json-output` / `-j` — Output results as JSON
- `--no-recommendations` — Skip recommendation generation
- `--check` / `-c` — Run only specific checks (cpu, memory, disk, io, network, load, sar)
- `--threshold` / `-t` — Threshold profile: default, strict, or relaxed
- `--verbose` / `-v` — Show verbose output (analyzenode)
- `--port` / `-p` — Node exporter port (default: 9100, analyzenode only)

## Project Structure

```
src/linuxdoctor/
├── __init__.py          # Package init with re-exports
├── cli.py               # Click CLI entry point
├── analyze.py            # Local host analysis (sar, vmstat, etc.)
├── analyzenode.py        # Remote node analysis (node_exporter)
│                        #   Analysis functions return AnalysisResult objects
│                        #   Formatting separated into _format_human/_format_json
├── collectors.py         # Local metric collectors
├── recommendations.py    # Local recommendation engine
├── prometheus.py         # Prometheus host discovery
└── node_analyzer.py      # Re-export of analyzenode for compatibility
```

## Requirements

- Linux system with standard performance tools for local analysis: `sar` (sysstat), `vmstat`, `iostat`, `mpstat`, `free`, `df`, `perf`, `uptime`
- Remote node analysis requires a running `node_exporter` on the target host
- `list-hosts` requires access to a Prometheus server API
- Python 3.9+

## License

MIT