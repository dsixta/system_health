# System Health Checker

A Python tool for IT Help Desk and sysadmins to quickly assess the health of a Windows system. Monitors CPU, memory, disk, network, and critical services — no dependencies required.

## Features

- **CPU Monitoring** — usage %, core count, frequency, top CPU-consuming processes
- **Memory Monitoring** — total/used/free RAM, usage %, top memory-consuming processes
- **Disk Monitoring** — all drives with usage stats, flags drives over 85% full
- **Network Monitoring** — active interfaces, IPs, bytes sent/received, connection count
- **Service Monitoring** — checks 12 critical Windows services (Defender, Windows Update, etc.)
- **Event Log Check** — last 5 critical/error events from the System log
- **Health Score** — weighted 0-100 score with visual bar (CPU 25%, RAM 25%, Disk 30%, Services 20%)
- **Recommendations** — actionable ITIL-style suggestions based on findings
- **Watch Mode** — auto-refresh display every N seconds
- **JSON output** — pipe results to other tools

## Usage

```bash
# Quick summary
python system_health.py

# Full report (all sections)
python system_health.py --full

# Auto-refresh every 5 seconds (like Task Manager)
python system_health.py --watch 5

# Save report to file
python system_health.py --full --output report.txt
python system_health.py --output metrics.csv

# JSON output for scripting
python system_health.py --json

# Plain text (no color)
python system_health.py --no-color
```

## Installation

```bash
git clone https://github.com/dsixta/system_health.git
cd system_health

# Run immediately — no install needed
python system_health.py

# Optional: install enhanced dependencies
pip install -r requirements.txt
```

## Requirements

- Python 3.8+
- Windows 10/11 (primary), Linux/Mac supported with reduced features
- No required dependencies — uses ctypes/WMI/subprocess fallbacks
- Optional: `psutil`, `pywin32`, `colorama`

## Skills Demonstrated

- Windows system internals (ctypes, WMI, Win32 API)
- IT Help Desk troubleshooting workflows
- Service monitoring and health scoring
- Multi-threaded data collection
- CLI tool design with multiple output formats
