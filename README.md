# linuxdoctor

Analyze performance metrics and recommend a course of action to resolve performance issues on Linux systems.

## Installation

```bash
pip install .
```

## Usage

### Analyze the current host

```bash
linuxdoctor analyze
```

Runs traditional analysis tools (sar, perf, vmstat, etc.) to gather performance metrics and provides recommendations for improving system health.

### Analyze a remote node

```bash
linuxdoctor analyzenode <node-address>
```

Analyzes a remote node (using node_exporter-style metrics).

## CLI Commands

- `analyze` - Analyze the current host using local performance tools
- `analyzenode` - Analyze a remote node using node_exporter metrics

## Requirements

- Linux system with standard performance tools: `sar` (sysstat), `vmstat`, `iostat`, `mpstat`, `free`, `df`, `perf`, `uptime`
- Python 3.9+

## License

MIT
