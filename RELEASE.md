## 0.2.0

- **Counter-aware remote analysis**: The `analyzenode` command now handles cumulative counter metrics correctly. Use `--resample` to take two samples and compute accurate per-second rates for context switches and disk I/O — no more false positives on long-running systems.
- **SSH-based metric collection**: New `registerhost --sshconnect` option lets linuxdoctor gather metrics via SSH using mpstat, iostat, and /proc instead of requiring node_exporter. Hosts without node_exporter can now be analyzed.
- **Host registry**: New `registerhost`, `list-registered`, and `unregisterhost` commands store host metadata (CPU core count, SSH connection string) for more accurate per-core analysis. Context switch rates are now normalized by registered core count.
- **Web dashboard**: New `linuxdoctor web` command starts a visual dashboard that periodically rescans registered hosts and shows color-coded health indicators for CPU, context switching, I/O wait, and disk — click any host for a full analysis.
- **Diagnostic tool suggestions**: When remote hosts are missing tools like `mpstat`, `iostat`, or `perf`, linuxdoctor now suggests the exact install command.

## 0.1.0 Initial Release

- Tool to analyze prometheus node exporter data to make recommendation about the health
  of the node_exporter host.
- more features to come
