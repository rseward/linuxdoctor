# Ticket #221: LinuxDoctor - Threshold & Sampling Recommendations for I/O Time and Context Switches

## Problem Statement

The linuxdoctor tool appears to frequently flag issues with two specific performance metrics:
1. **I/O time** (iowait / disk I/O utilization)
2. **Context switches** (context switch rate)

The ticket hypothesizes that these metrics may be **cumulative counters** rather than instantaneous gauges, which could cause false positives if the tool reads raw values without computing rates first.

## Key Finding: Metrics Are Cumulative Counters

This hypothesis is **correct**. Both metrics from the Prometheus `node_exporter` are **counters** that accumulate since boot:

- `node_cpu_seconds_total{mode="iowait"}` — cumulative seconds spent in I/O wait state
- `node_context_switches_total` — cumulative number of context switches since boot

Reading these values directly gives a monotonically increasing number that is **meaningless as a threshold** without computing a rate over a time window.

## Recommended Approach

### 1. Use `rate()` or `increase()` — Never Raw Counter Values

**Context Switches:**
```promql
# Rate of context switches per second over a 5-minute window
rate(node_context_switches_total[5m])
```

**I/O Wait:**
```promql
# Percentage of CPU time spent in iowait over 5 minutes
rate(node_cpu_seconds_total{mode="iowait"}[5m]) * 100
```

**Disk I/O Utilization:**
```promql
# Percentage of time the disk was busy over 5 minutes
rate(node_disk_io_time_seconds_total[5m]) * 100
```

### 2. Take Multiple Samples (Confirm the Ticket's Hypothesis)

A single sample of a rate can still be noisy. The best practice is to:
- Compute `rate()` over a **5-minute window** (requires Prometheus, not just node_exporter)
- If querying node_exporter directly (no Prometheus), take **at least 2-3 samples** at intervals (e.g., 30-60 seconds apart) and compute the delta yourself
- This smooths out transient spikes and avoids false positives from momentary bursts

### 3. Threshold Recommendations

#### I/O Wait (as % of CPU time)

| Level | Threshold | Notes |
|-------|-----------|-------|
| Normal | < 5% | Healthy system |
| Warning | > 20% sustained for 15 min | I/O bottleneck developing |
| Critical | > 50% sustained for 5 min | Severe I/O starvation |

**PromQL Alert Rules:**
```yaml
- alert: HostHighIOwait
  expr: (rate(node_cpu_seconds_total{mode="iowait"}[5m]) * 100) > 20
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "CPU I/O wait high on {{ $labels.instance }}"
    description: "I/O wait is {{ $value | printf \"%.1f\" }}% of CPU time"

- alert: HostCriticalIOwait
  expr: (rate(node_cpu_seconds_total{mode="iowait"}[5m]) * 100) > 50
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "CPU I/O wait critical on {{ $labels.instance }}"
    description: "I/O wait is {{ $value | printf \"%.1f\" }}% of CPU time"
```

#### Context Switch Rate (per second)

Context switch thresholds are **highly dependent on the number of CPU cores**. A rate of 5,000/s might be fine on a 64-core system but terrible on a single-core VM.

**Normalized approach (switches per core per second):**
```promql
rate(node_context_switches_total[5m]) / on(instance) count(node_cpu_seconds_total{mode="idle"}) by (instance)
```

| Level | Switches/core/sec | Notes |
|-------|-------------------|-------|
| Normal | < 500 | Healthy |
| Warning | > 1,000 sustained 15 min | Possible contention |
| Critical | > 5,000 sustained 5 min | Severe scheduling issues |

**Absolute approach (total switches/sec):**
| Cores | Warning | Critical |
|-------|---------|----------|
| 1-2 | > 2,000/s | > 10,000/s |
| 4-8 | > 10,000/s | > 50,000/s |
| 16-32 | > 30,000/s | > 100,000/s |
| 64+ | > 100,000/s | > 500,000/s |

**PromQL Alert Rules:**
```yaml
- alert: HighContextSwitchRate
  expr: rate(node_context_switches_total[5m]) / on(instance) count(node_cpu_seconds_total{mode="idle"}) by (instance) > 1000
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "High context switch rate on {{ $labels.instance }}"
    description: "Context switch rate is {{ $value | printf \"%.0f\" }} per core per second"

- alert: CriticalContextSwitchRate
  expr: rate(node_context_switches_total[5m]) / on(instance) count(node_cpu_seconds_total{mode="idle"}) by (instance) > 5000
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Critical context switch rate on {{ $labels.instance }}"
    description: "Context switch rate is {{ $value | printf \"%.0f\" }} per core per second"
```

#### Disk I/O Utilization (% of time device is busy)

| Level | Threshold | Notes |
|-------|-----------|-------|
| Normal | < 50% | Healthy |
| Warning | > 70% sustained 10 min | Disk under pressure |
| Critical | > 90% sustained 5 min | Disk saturated |

**PromQL Alert Rule:**
```yaml
- alert: HostHighDiskIO
  expr: rate(node_disk_io_time_seconds_total[5m]) * 100 > 70
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Disk I/O busy on {{ $labels.instance }} device {{ $labels.device }}"
    description: "I/O utilization is {{ $value | printf \"%.1f\" }}%"
```

### 4. Implementation Recommendations for linuxdoctor

If linuxdoctor queries `node_exporter` metrics directly (without Prometheus), it needs to:

1. **Never compare raw counter values to static thresholds.** Always compute rate = (current_value - previous_value) / time_elapsed_seconds.

2. **Store previous sample values** for each metric per host. On each check:
   ```
   rate = (current_counter - previous_counter) / (current_timestamp - previous_timestamp)
   ```

3. **Discard the first sample.** Since there's no previous value, the first check cannot compute a rate. Skip it.

4. **Handle counter resets.** If `current < previous`, the counter likely reset (e.g., reboot). Use the current value as baseline.

5. **Require sustained violations.** Use a "consecutive failure threshold" (e.g., 3 consecutive checks above threshold before alerting), similar to how node-doctor uses `sustainedHighLoadChecks: 3`. This prevents false positives from transient spikes.

6. **Normalize by CPU count.** For context switches, divide by the number of CPU cores to make thresholds meaningful across different machine sizes.

### 5. Why False Positives Occur

The ticket correctly identifies the root cause:

- **`node_context_switches_total`** is a CUMULATIVE counter from `/proc/stat` (ctxt field). It only resets on boot. Reading it once gives you the total since boot — e.g., 500,000,000 — which looks alarming but is completely normal for a system that's been up for 30 days.

- **`node_cpu_seconds_total{mode="iowait"}`** is also a cumulative counter. A raw value of 45,000 seconds of iowait means nothing without knowing the total CPU time and the observation window.

- **`node_disk_io_time_seconds_total`** is similarly cumulative.

Without computing `rate()` or taking deltas, ANY threshold comparison on these metrics will produce constant false positives on long-running systems.

## Sources

- Prometheus node_exporter official mixin alert rules
- StackOverflow: "What is rate node_context_switches_total" — confirms it's a counter requiring `rate()`
- Node-doctor (SupportTools/node-doctor) — uses `sustainedHighLoadChecks` pattern to prevent false positives
- BestHub: "Master Linux Host Monitoring" — comprehensive threshold reference