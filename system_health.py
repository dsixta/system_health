#!/usr/bin/env python3
"""
system_health.py — System Health Monitor for IT Help Desk / Cybersecurity Portfolio
Author: IT Help Desk Toolkit
Python 3.8+ | Windows Primary | Linux/Mac fallback
Dependencies: None required (psutil/colorama/pywin32 optional for enhanced output)

Usage:
    python system_health.py              # Summary view
    python system_health.py --full       # All sections
    python system_health.py --json       # JSON output
    python system_health.py --output report.txt
    python system_health.py --watch 5    # Refresh every 5 seconds
    python system_health.py --full --output report.csv
"""

import argparse
import csv
import datetime
import io
import json
import os
import platform
import socket
import subprocess
import sys
import time
import threading
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ── Force UTF-8 stdout/stderr so Unicode characters (bars, boxes) render
# correctly on Windows terminals regardless of the system codepage.
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Optional dependency detection — graceful fallback at every level
# ─────────────────────────────────────────────────────────────────────────────

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import colorama
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"

# ─────────────────────────────────────────────────────────────────────────────
# ANSI Color Helpers — fall back to plain text if terminal doesn't support it
# ─────────────────────────────────────────────────────────────────────────────

class Color:
    """ANSI escape codes for terminal coloring.

    In IT contexts, color-coded output helps analysts quickly spot issues:
    RED = critical problem, YELLOW = warning, GREEN = healthy, CYAN = informational.
    """
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

    # Check if we should use colors (stdout is a real terminal or colorama is available)
    _enabled: bool = HAS_COLORAMA or (hasattr(sys.stdout, "isatty") and sys.stdout.isatty())

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False

    @classmethod
    def _c(cls, code: str, text: str) -> str:
        if cls._enabled:
            return f"{code}{text}{cls.RESET}"
        return text

    @classmethod
    def red(cls, t: str)     -> str: return cls._c(cls.RED, t)
    @classmethod
    def yellow(cls, t: str)  -> str: return cls._c(cls.YELLOW, t)
    @classmethod
    def green(cls, t: str)   -> str: return cls._c(cls.GREEN, t)
    @classmethod
    def cyan(cls, t: str)    -> str: return cls._c(cls.CYAN, t)
    @classmethod
    def blue(cls, t: str)    -> str: return cls._c(cls.BLUE, t)
    @classmethod
    def magenta(cls, t: str) -> str: return cls._c(cls.MAGENTA, t)
    @classmethod
    def bold(cls, t: str)    -> str: return cls._c(cls.BOLD, t)
    @classmethod
    def dim(cls, t: str)     -> str: return cls._c(cls.DIM, t)
    @classmethod
    def white(cls, t: str)   -> str: return cls._c(cls.WHITE, t)


def progress_bar(value: float, total: float = 100.0, width: int = 30,
                 warn: float = 70.0, crit: float = 85.0) -> str:
    """
    Render an ASCII progress bar with color thresholds.

    Thresholds used across the industry for resource monitoring:
      - <70%  = Normal (green)
      - 70-85% = Warning (yellow) — investigate if trending up
      - >85%  = Critical (red) — immediate attention required

    Args:
        value: Current value (e.g., 75.3 for CPU%)
        total: Maximum value (default 100 for percentages)
        width: Bar character width
        warn:  Yellow threshold
        crit:  Red threshold

    Returns:
        Colored ASCII progress bar string like: [████████░░░░] 53.2%
    """
    pct = min(max(value / total * 100, 0), 100)
    filled = int(width * pct / 100)
    bar_chars = "█" * filled + "░" * (width - filled)
    label = f"{pct:5.1f}%"

    if pct >= crit:
        bar_str = Color.red(f"[{bar_chars}]")
        lbl_str = Color.red(label)
    elif pct >= warn:
        bar_str = Color.yellow(f"[{bar_chars}]")
        lbl_str = Color.yellow(label)
    else:
        bar_str = Color.green(f"[{bar_chars}]")
        lbl_str = Color.green(label)

    return f"{bar_str} {lbl_str}"


def human_bytes(num: float, suffix: str = "B") -> str:
    """Convert raw bytes to a human-readable string (KB, MB, GB, TB)."""
    for unit in ("", "K", "M", "G", "T", "P"):
        if abs(num) < 1024.0:
            return f"{num:6.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f} E{suffix}"


def section_header(title: str, width: int = 70) -> str:
    """Format a visually distinct section header for the report."""
    line = "─" * width
    return f"\n{Color.bold(Color.cyan(line))}\n  {Color.bold(Color.white(title))}\n{Color.bold(Color.cyan(line))}"


def fmt_timestamp(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Data Collection Classes — one per metric category
# ─────────────────────────────────────────────────────────────────────────────

class SystemInfo:
    """
    Collects basic system identification and uptime information.

    IT Relevance:
      - Hostname confirms you're on the right machine before running diagnostics.
      - Uptime reveals if a system has missed required reboots (e.g., pending
        Windows Update), or has been running so long it needs maintenance.
      - OS version is critical for patch-level assessment and CVE applicability.
    """

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        data["hostname"]   = socket.gethostname()
        data["platform"]   = platform.system()
        data["os_version"] = platform.version()
        data["os_release"] = platform.release()
        data["machine"]    = platform.machine()
        data["processor"]  = platform.processor() or "Unknown"
        data["python"]     = platform.python_version()

        # Attempt to get FQDN (useful in domain environments)
        try:
            data["fqdn"] = socket.getfqdn()
        except Exception:
            data["fqdn"] = data["hostname"]

        # Boot time — psutil gives the most reliable result
        if HAS_PSUTIL:
            boot_ts = psutil.boot_time()
            boot_dt = datetime.datetime.fromtimestamp(boot_ts)
            data["boot_time"] = fmt_timestamp(boot_dt)
            uptime_secs = time.time() - boot_ts
        elif IS_WINDOWS:
            uptime_secs = self._windows_uptime()
            if uptime_secs:
                boot_dt = datetime.datetime.now() - datetime.timedelta(seconds=uptime_secs)
                data["boot_time"] = fmt_timestamp(boot_dt)
            else:
                data["boot_time"] = "Unavailable"
        elif IS_LINUX:
            uptime_secs = self._linux_uptime()
            if uptime_secs:
                boot_dt = datetime.datetime.now() - datetime.timedelta(seconds=uptime_secs)
                data["boot_time"] = fmt_timestamp(boot_dt)
            else:
                data["boot_time"] = "Unavailable"
        else:
            uptime_secs = 0
            data["boot_time"] = "Unavailable"

        if uptime_secs:
            data["uptime_seconds"] = int(uptime_secs)
            data["uptime_human"]   = self._format_uptime(uptime_secs)
        else:
            data["uptime_seconds"] = 0
            data["uptime_human"]   = "Unavailable"

        return data

    @staticmethod
    def _windows_uptime() -> Optional[float]:
        """Query uptime via GetTickCount64 (milliseconds since last boot)."""
        if HAS_CTYPES:
            try:
                ms = ctypes.windll.kernel32.GetTickCount64()
                return ms / 1000.0
            except Exception:
                pass
        # Fallback: parse systeminfo output
        try:
            out = subprocess.check_output(
                ["systeminfo"], text=True, stderr=subprocess.DEVNULL, timeout=30
            )
            for line in out.splitlines():
                if "System Boot Time" in line or "Boot Time" in line:
                    # e.g. "System Boot Time:          3/14/2025, 9:00:00 AM"
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        raw = parts[1].strip()
                        for fmt in ("%m/%d/%Y, %I:%M:%S %p", "%d/%m/%Y, %H:%M:%S"):
                            try:
                                boot_dt = datetime.datetime.strptime(raw, fmt)
                                return (datetime.datetime.now() - boot_dt).total_seconds()
                            except ValueError:
                                pass
        except Exception:
            pass
        return None

    @staticmethod
    def _linux_uptime() -> Optional[float]:
        """Read /proc/uptime — first field is seconds since boot."""
        try:
            with open("/proc/uptime") as f:
                return float(f.read().split()[0])
        except Exception:
            return None

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        days, rem   = divmod(int(seconds), 86400)
        hours, rem  = divmod(rem, 3600)
        minutes, _  = divmod(rem, 60)
        parts = []
        if days:    parts.append(f"{days}d")
        if hours:   parts.append(f"{hours}h")
        if minutes: parts.append(f"{minutes}m")
        return " ".join(parts) if parts else "< 1m"


class CPUInfo:
    """
    Collects CPU utilisation, frequency, core counts, and top consumers.

    IT Relevance:
      - Sustained CPU >85% can indicate malware, runaway processes, or the need
        to scale hardware.
      - Frequency throttling (current << max) often signals thermal issues or
        power-saving mode — common on laptops during remote diagnosis.
      - Top-5 process list lets you pinpoint offending applications instantly
        without opening Task Manager.
    """

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        if HAS_PSUTIL:
            data["usage_pct"]      = psutil.cpu_percent(interval=1)
            data["core_count"]     = psutil.cpu_count(logical=False) or 1
            data["logical_count"]  = psutil.cpu_count(logical=True)  or 1
            freq = psutil.cpu_freq()
            if freq:
                data["freq_current"] = round(freq.current, 1)
                data["freq_min"]     = round(freq.min, 1)
                data["freq_max"]     = round(freq.max, 1)
            else:
                data["freq_current"] = data["freq_min"] = data["freq_max"] = 0.0
            data["top_processes"]  = self._top_procs_psutil()
        elif IS_WINDOWS:
            data["usage_pct"]     = self._windows_cpu_usage()
            data["core_count"]    = self._windows_core_count()
            data["logical_count"] = os.cpu_count() or 1
            data["freq_current"]  = self._windows_cpu_freq()
            data["freq_min"]      = 0.0
            data["freq_max"]      = data["freq_current"]
            data["top_processes"] = self._windows_top_procs()
        elif IS_LINUX:
            data["usage_pct"]     = self._linux_cpu_usage()
            data["core_count"]    = os.cpu_count() or 1
            data["logical_count"] = os.cpu_count() or 1
            data["freq_current"]  = self._linux_cpu_freq()
            data["freq_min"]      = 0.0
            data["freq_max"]      = data["freq_current"]
            data["top_processes"] = self._linux_top_procs()
        else:
            data = {
                "usage_pct": 0.0, "core_count": os.cpu_count() or 1,
                "logical_count": os.cpu_count() or 1,
                "freq_current": 0.0, "freq_min": 0.0, "freq_max": 0.0,
                "top_processes": []
            }

        return data

    # ── psutil helpers ────────────────────────────────────────────────────────
    @staticmethod
    def _top_procs_psutil(n: int = 5) -> List[Dict]:
        """Use psutil to find top CPU-consuming processes (1-second sample)."""
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "status"]):
            try:
                procs.append({
                    "pid":  p.info["pid"],
                    "name": p.info["name"] or "Unknown",
                    "cpu":  p.info["cpu_percent"] or 0.0,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        # cpu_percent requires two calls; first call returns 0 for each process.
        # Re-sample after brief pause for accuracy.
        time.sleep(0.5)
        result = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
            try:
                result.append({
                    "pid":  p.info["pid"],
                    "name": p.info["name"] or "Unknown",
                    "cpu":  p.info["cpu_percent"] or 0.0,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(result, key=lambda x: x["cpu"], reverse=True)[:n]

    # ── Windows fallbacks ─────────────────────────────────────────────────────
    @staticmethod
    def _windows_cpu_usage() -> float:
        """WMIC query for CPU load percentage."""
        try:
            out = subprocess.check_output(
                ["wmic", "cpu", "get", "LoadPercentage"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    return float(line)
        except Exception:
            pass
        return 0.0

    @staticmethod
    def _windows_core_count() -> int:
        """WMIC query for physical core count."""
        try:
            out = subprocess.check_output(
                ["wmic", "cpu", "get", "NumberOfCores"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    return int(line)
        except Exception:
            pass
        return os.cpu_count() or 1

    @staticmethod
    def _windows_cpu_freq() -> float:
        """Read CPU max clock speed via WMIC (MHz)."""
        try:
            out = subprocess.check_output(
                ["wmic", "cpu", "get", "MaxClockSpeed"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    return float(line)
        except Exception:
            pass
        return 0.0

    @staticmethod
    def _windows_top_procs(n: int = 5) -> List[Dict]:
        """Tasklist + sort by memory as CPU% proxy (WMIC is slow for all procs)."""
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            procs = []
            import csv as _csv
            for row in _csv.reader(out.splitlines()):
                if len(row) >= 5:
                    name = row[0].strip('"')
                    pid  = row[1].strip('"')
                    mem  = row[4].strip('"').replace(",", "").replace(" K", "")
                    try:
                        procs.append({"pid": int(pid), "name": name, "cpu": 0.0,
                                       "mem_kb": int(mem)})
                    except ValueError:
                        pass
            return sorted(procs, key=lambda x: x.get("mem_kb", 0), reverse=True)[:n]
        except Exception:
            return []

    # ── Linux fallbacks ───────────────────────────────────────────────────────
    @staticmethod
    def _linux_cpu_usage() -> float:
        """Parse /proc/stat for aggregate CPU idle time, sample twice."""
        def _read():
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:]))
            idle  = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            return idle, total
        try:
            i1, t1 = _read()
            time.sleep(0.5)
            i2, t2 = _read()
            idle_d  = i2 - i1
            total_d = t2 - t1
            return round(100.0 * (1 - idle_d / total_d), 1) if total_d else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _linux_cpu_freq() -> float:
        """Read /proc/cpuinfo for cpu MHz."""
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("cpu MHz"):
                        return float(line.split(":")[1].strip())
        except Exception:
            pass
        return 0.0

    @staticmethod
    def _linux_top_procs(n: int = 5) -> List[Dict]:
        try:
            out = subprocess.check_output(
                ["ps", "aux", "--sort=-%cpu"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            procs = []
            for line in out.splitlines()[1:n+1]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({
                        "pid":  int(parts[1]),
                        "name": parts[10][:40],
                        "cpu":  float(parts[2]),
                    })
            return procs
        except Exception:
            return []


class MemoryInfo:
    """
    Collects RAM utilisation and top memory-consuming processes.

    IT Relevance:
      - High memory usage (>85%) causes the OS to swap to disk, dramatically
        slowing the system — a common user complaint root cause.
      - Identifying the top memory consumer lets you advise "close Chrome tabs"
        or escalate to a developer for a memory-leak investigation.
      - Virtual memory (page file) stats reveal swap pressure on Windows.
    """

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        if HAS_PSUTIL:
            vm = psutil.virtual_memory()
            sw = psutil.swap_memory()
            data["total"]       = vm.total
            data["used"]        = vm.used
            data["available"]   = vm.available
            data["usage_pct"]   = vm.percent
            data["swap_total"]  = sw.total
            data["swap_used"]   = sw.used
            data["swap_pct"]    = sw.percent
            data["top_processes"] = self._top_procs_psutil()
        elif IS_WINDOWS:
            ram = self._windows_ram()
            data.update(ram)
            data["top_processes"] = self._windows_top_procs()
        elif IS_LINUX:
            ram = self._linux_ram()
            data.update(ram)
            data["top_processes"] = self._linux_top_procs()
        else:
            data = {
                "total": 0, "used": 0, "available": 0, "usage_pct": 0.0,
                "swap_total": 0, "swap_used": 0, "swap_pct": 0.0,
                "top_processes": []
            }

        return data

    @staticmethod
    def _top_procs_psutil(n: int = 5) -> List[Dict]:
        result = []
        for p in psutil.process_iter(["pid", "name", "memory_info", "memory_percent"]):
            try:
                mi = p.info["memory_info"]
                result.append({
                    "pid":    p.info["pid"],
                    "name":   p.info["name"] or "Unknown",
                    "mem_b":  mi.rss if mi else 0,
                    "mem_pct": round(p.info["memory_percent"] or 0.0, 2),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(result, key=lambda x: x["mem_b"], reverse=True)[:n]

    @staticmethod
    def _windows_ram() -> Dict:
        """Use GlobalMemoryStatusEx via ctypes for accurate Windows RAM figures."""
        if HAS_CTYPES:
            try:
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength",                ctypes.c_ulong),
                        ("dwMemoryLoad",            ctypes.c_ulong),
                        ("ullTotalPhys",             ctypes.c_ulonglong),
                        ("ullAvailPhys",             ctypes.c_ulonglong),
                        ("ullTotalPageFile",         ctypes.c_ulonglong),
                        ("ullAvailPageFile",         ctypes.c_ulonglong),
                        ("ullTotalVirtual",          ctypes.c_ulonglong),
                        ("ullAvailVirtual",          ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual",  ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                total     = stat.ullTotalPhys
                available = stat.ullAvailPhys
                used      = total - available
                return {
                    "total":       total,
                    "used":        used,
                    "available":   available,
                    "usage_pct":   round(used / total * 100, 1) if total else 0.0,
                    "swap_total":  stat.ullTotalPageFile,
                    "swap_used":   stat.ullTotalPageFile - stat.ullAvailPageFile,
                    "swap_pct":    0.0,
                }
            except Exception:
                pass
        # WMIC fallback
        try:
            out = subprocess.check_output(
                ["wmic", "OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith("Total"):
                    parts = line.split()
                    if len(parts) == 2 and all(p.isdigit() for p in parts):
                        free_kb  = int(parts[0])
                        total_kb = int(parts[1])
                        total    = total_kb * 1024
                        free     = free_kb  * 1024
                        used     = total - free
                        return {
                            "total":      total,
                            "used":       used,
                            "available":  free,
                            "usage_pct":  round(used / total * 100, 1) if total else 0.0,
                            "swap_total": 0,
                            "swap_used":  0,
                            "swap_pct":   0.0,
                        }
        except Exception:
            pass
        return {"total": 0, "used": 0, "available": 0, "usage_pct": 0.0,
                "swap_total": 0, "swap_used": 0, "swap_pct": 0.0}

    @staticmethod
    def _windows_top_procs(n: int = 5) -> List[Dict]:
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            procs = []
            import csv as _csv
            for row in _csv.reader(out.splitlines()):
                if len(row) >= 5:
                    name = row[0].strip('"')
                    pid  = row[1].strip('"')
                    mem  = row[4].strip('"').replace(",", "").replace(" K", "")
                    try:
                        mem_b = int(mem) * 1024
                        procs.append({"pid": int(pid), "name": name,
                                       "mem_b": mem_b, "mem_pct": 0.0})
                    except ValueError:
                        pass
            return sorted(procs, key=lambda x: x["mem_b"], reverse=True)[:n]
        except Exception:
            return []

    @staticmethod
    def _linux_ram() -> Dict:
        try:
            info = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        info[parts[0].rstrip(":")] = int(parts[1]) * 1024
            total     = info.get("MemTotal", 0)
            free      = info.get("MemFree",  0)
            available = info.get("MemAvailable", free)
            used      = total - available
            swap_total = info.get("SwapTotal", 0)
            swap_free  = info.get("SwapFree",  0)
            swap_used  = swap_total - swap_free
            return {
                "total":      total,
                "used":       used,
                "available":  available,
                "usage_pct":  round(used / total * 100, 1) if total else 0.0,
                "swap_total": swap_total,
                "swap_used":  swap_used,
                "swap_pct":   round(swap_used / swap_total * 100, 1) if swap_total else 0.0,
            }
        except Exception:
            return {"total": 0, "used": 0, "available": 0, "usage_pct": 0.0,
                    "swap_total": 0, "swap_used": 0, "swap_pct": 0.0}

    @staticmethod
    def _linux_top_procs(n: int = 5) -> List[Dict]:
        try:
            out = subprocess.check_output(
                ["ps", "aux", "--sort=-%mem"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            procs = []
            for line in out.splitlines()[1:n+1]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({
                        "pid":     int(parts[1]),
                        "name":    parts[10][:40],
                        "mem_b":   int(parts[5]) * 1024,
                        "mem_pct": float(parts[3]),
                    })
            return procs
        except Exception:
            return []


class DiskInfo:
    """
    Collects disk partition usage and I/O statistics.

    IT Relevance:
      - A full disk (>95%) can cause application crashes, failed updates, and
        system instability — this is one of the most common Help Desk tickets.
      - Flagging drives >85% early gives time for proactive cleanup before
        an outage occurs.
      - Read/write stats help identify disk thrashing (I/O bottleneck), which
        can masquerade as CPU slowness to end users.
    """

    # Drives >85% usage warrant a warning in the health report
    WARN_THRESHOLD = 85.0
    CRIT_THRESHOLD = 95.0

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"partitions": [], "io_stats": {}}

        if HAS_PSUTIL:
            data["partitions"] = self._partitions_psutil()
            data["io_stats"]   = self._io_stats_psutil()
        elif IS_WINDOWS:
            data["partitions"] = self._windows_partitions()
            data["io_stats"]   = {}
        elif IS_LINUX:
            data["partitions"] = self._linux_partitions()
            data["io_stats"]   = self._linux_io_stats()
        else:
            data["partitions"] = []
            data["io_stats"]   = {}

        # Flag any partition over the warning threshold
        for p in data["partitions"]:
            pct = p.get("usage_pct", 0)
            if pct >= self.CRIT_THRESHOLD:
                p["status"] = "CRITICAL"
            elif pct >= self.WARN_THRESHOLD:
                p["status"] = "WARNING"
            else:
                p["status"] = "OK"

        return data

    @staticmethod
    def _partitions_psutil() -> List[Dict]:
        parts = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                parts.append({
                    "device":     part.device,
                    "mountpoint": part.mountpoint,
                    "fstype":     part.fstype,
                    "total":      usage.total,
                    "used":       usage.used,
                    "free":       usage.free,
                    "usage_pct":  usage.percent,
                })
            except (PermissionError, OSError):
                pass
        return parts

    @staticmethod
    def _io_stats_psutil() -> Dict:
        try:
            io = psutil.disk_io_counters(perdisk=False)
            if io:
                return {
                    "read_bytes":  io.read_bytes,
                    "write_bytes": io.write_bytes,
                    "read_count":  io.read_count,
                    "write_count": io.write_count,
                }
        except Exception:
            pass
        return {}

    @staticmethod
    def _windows_partitions() -> List[Dict]:
        """Enumerate Windows drives A–Z and query free space via ctypes."""
        parts = []
        drives = []
        if HAS_CTYPES:
            try:
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for i in range(26):
                    if bitmask & (1 << i):
                        drives.append(chr(65 + i) + ":\\")
            except Exception:
                drives = ["C:\\"]
        else:
            drives = ["C:\\"]

        for drive in drives:
            if HAS_CTYPES:
                try:
                    free_b  = ctypes.c_ulonglong(0)
                    total_b = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        drive,
                        ctypes.byref(free_b),
                        ctypes.byref(total_b),
                        None
                    )
                    if total_b.value > 0:
                        used  = total_b.value - free_b.value
                        parts.append({
                            "device":     drive,
                            "mountpoint": drive,
                            "fstype":     "NTFS",
                            "total":      total_b.value,
                            "used":       used,
                            "free":       free_b.value,
                            "usage_pct":  round(used / total_b.value * 100, 1),
                        })
                except Exception:
                    pass
        return parts

    @staticmethod
    def _linux_partitions() -> List[Dict]:
        """Parse /proc/mounts and use os.statvfs for usage."""
        parts = []
        try:
            with open("/proc/mounts") as f:
                mounts = f.readlines()
            seen = set()
            for line in mounts:
                cols = line.split()
                if len(cols) < 3:
                    continue
                device, mountpoint, fstype = cols[0], cols[1], cols[2]
                # Skip pseudo-filesystems
                if fstype in ("tmpfs", "devtmpfs", "sysfs", "proc", "devpts",
                              "cgroup", "cgroup2", "pstore", "bpf", "tracefs",
                              "debugfs", "securityfs", "configfs", "fusectl"):
                    continue
                if mountpoint in seen:
                    continue
                seen.add(mountpoint)
                try:
                    stat = os.statvfs(mountpoint)
                    total = stat.f_blocks * stat.f_frsize
                    free  = stat.f_bfree  * stat.f_frsize
                    avail = stat.f_bavail * stat.f_frsize
                    used  = total - free
                    if total == 0:
                        continue
                    parts.append({
                        "device":     device,
                        "mountpoint": mountpoint,
                        "fstype":     fstype,
                        "total":      total,
                        "used":       used,
                        "free":       avail,
                        "usage_pct":  round(used / total * 100, 1),
                    })
                except (PermissionError, OSError):
                    pass
        except Exception:
            pass
        return parts

    @staticmethod
    def _linux_io_stats() -> Dict:
        """Parse /proc/diskstats for aggregate block device I/O."""
        try:
            read_b = write_b = read_c = write_c = 0
            with open("/proc/diskstats") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 14:
                        # sectors are 512 bytes each
                        read_c  += int(parts[3])
                        read_b  += int(parts[5])  * 512
                        write_c += int(parts[7])
                        write_b += int(parts[9])  * 512
            return {
                "read_bytes":  read_b,
                "write_bytes": write_b,
                "read_count":  read_c,
                "write_count": write_c,
            }
        except Exception:
            return {}


class NetworkInfo:
    """
    Collects network interface details, I/O counters, and active connection count.

    IT Relevance:
      - Unexpected outbound connections can indicate data exfiltration or C2
        (Command & Control) activity — first-line indicator of compromise.
      - High bytes-sent on an idle machine raises immediate red flags.
      - Multiple interfaces with missing IPs can indicate DHCP failures.
      - Connection counts spike during malware lateral-movement attempts.
    """

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        if HAS_PSUTIL:
            data["interfaces"]        = self._interfaces_psutil()
            data["io_stats"]          = self._io_psutil()
            data["connection_count"]  = self._connections_psutil()
        else:
            data["interfaces"]        = self._interfaces_fallback()
            data["io_stats"]          = self._io_fallback()
            data["connection_count"]  = self._connections_fallback()

        return data

    @staticmethod
    def _interfaces_psutil() -> List[Dict]:
        ifaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ipv4 = [a.address for a in addr_list
                    if a.family == socket.AF_INET]
            ipv6 = [a.address for a in addr_list
                    if a.family == socket.AF_INET6]
            mac  = [a.address for a in addr_list
                    if a.family not in (socket.AF_INET, socket.AF_INET6)]
            st   = stats.get(name)
            ifaces.append({
                "name":    name,
                "ipv4":    ipv4,
                "ipv6":    ipv6,
                "mac":     mac[0] if mac else "N/A",
                "is_up":   st.isup if st else False,
                "speed":   st.speed if st else 0,
            })
        return ifaces

    @staticmethod
    def _io_psutil() -> Dict:
        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent":   io.bytes_sent,
                "bytes_recv":   io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errin":        io.errin,
                "errout":       io.errout,
            }
        except Exception:
            return {}

    @staticmethod
    def _connections_psutil() -> int:
        try:
            return len(psutil.net_connections())
        except Exception:
            return 0

    @staticmethod
    def _interfaces_fallback() -> List[Dict]:
        """Use socket.getaddrinfo as a minimal interface probe."""
        ifaces = []
        try:
            hostname = socket.gethostname()
            ips = socket.getaddrinfo(hostname, None)
            seen = set()
            for item in ips:
                ip = item[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ifaces.append({
                        "name":   "default",
                        "ipv4":   [ip] if "." in ip else [],
                        "ipv6":   [ip] if ":" in ip else [],
                        "mac":    "N/A",
                        "is_up":  True,
                        "speed":  0,
                    })
        except Exception:
            pass
        return ifaces

    @staticmethod
    def _io_fallback() -> Dict:
        """Parse /proc/net/dev on Linux."""
        if IS_LINUX:
            try:
                rx = tx = 0
                with open("/proc/net/dev") as f:
                    for line in f.readlines()[2:]:
                        parts = line.split()
                        if len(parts) >= 10:
                            rx += int(parts[1])
                            tx += int(parts[9])
                return {"bytes_sent": tx, "bytes_recv": rx,
                        "packets_sent": 0, "packets_recv": 0,
                        "errin": 0, "errout": 0}
            except Exception:
                pass
        return {}

    @staticmethod
    def _connections_fallback() -> int:
        """Count lines in netstat output."""
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["netstat", "-n"], text=True, stderr=subprocess.DEVNULL, timeout=10
                )
            else:
                out = subprocess.check_output(
                    ["netstat", "-tn"], text=True, stderr=subprocess.DEVNULL, timeout=10
                )
            return sum(1 for line in out.splitlines()
                       if "ESTABLISHED" in line or "CONNECTED" in line)
        except Exception:
            return 0


class ServicesInfo:
    """
    Checks the status of critical Windows services.

    IT Relevance:
      - Stopped security services (Defender, Firewall) can indicate tampering,
        malware self-defense, or misconfiguration — a serious security finding.
      - Windows Update service must be running to receive patches; missing
        patches are the #1 attack vector in enterprise environments.
      - BITS (Background Intelligent Transfer) failures silently block updates.

    This check is Windows-only and gracefully returns empty on other platforms.
    """

    # Services that should always be running on a healthy Windows system
    CRITICAL_SERVICES = [
        ("WinDefend",       "Windows Defender Antivirus"),
        ("MpsSvc",          "Windows Firewall"),
        ("wuauserv",        "Windows Update"),
        ("BITS",            "Background Intelligent Transfer"),
        ("EventLog",        "Windows Event Log"),
        ("Dnscache",        "DNS Client"),
        ("LanmanWorkstation","Workstation (SMB Client)"),
        ("RpcSs",           "Remote Procedure Call"),
        ("W32Time",         "Windows Time"),
        ("CryptSvc",        "Cryptographic Services"),
        ("wscsvc",          "Security Center"),
        ("Schedule",        "Task Scheduler"),
    ]

    def collect(self) -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"available": False, "services": [], "stopped_critical": []}

        services = self._query_services()
        stopped_critical = [
            s for s in services
            if s["name"] in [c[0] for c in self.CRITICAL_SERVICES]
            and s["state"] != "Running"
        ]
        return {
            "available":        True,
            "services":         services,
            "stopped_critical": stopped_critical,
        }

    def _query_services(self) -> List[Dict]:
        """Query service status via sc.exe (available on all Windows versions)."""
        results = []
        for svc_name, friendly_name in self.CRITICAL_SERVICES:
            state = self._query_single_service(svc_name)
            results.append({
                "name":          svc_name,
                "friendly_name": friendly_name,
                "state":         state,
            })
        return results

    @staticmethod
    def _query_single_service(name: str) -> str:
        """Run 'sc query <name>' and parse the STATE line."""
        try:
            out = subprocess.check_output(
                ["sc", "query", name],
                text=True, stderr=subprocess.DEVNULL, timeout=8
            )
            for line in out.splitlines():
                if "STATE" in line:
                    # e.g. "        STATE              : 4  RUNNING"
                    if "RUNNING"      in line: return "Running"
                    if "STOPPED"      in line: return "Stopped"
                    if "START_PENDING" in line: return "Start Pending"
                    if "STOP_PENDING"  in line: return "Stop Pending"
                    if "PAUSED"        in line: return "Paused"
        except Exception:
            pass
        return "Unknown"


class EventLogInfo:
    """
    Reads the last N critical/error events from the Windows System Event Log.

    IT Relevance:
      - System errors logged right before a crash or slowdown are the primary
        clue in root-cause analysis.
      - Repeated Event IDs (e.g., 7034 = service crash, 41 = kernel power loss)
        indicate recurring hardware or driver issues.
      - This section requires pywin32 (win32evtlog) — skipped gracefully if
        unavailable so the rest of the report still runs.

    pywin32 install: pip install pywin32
    """

    def collect(self, max_events: int = 5) -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"available": False, "events": [], "reason": "Windows only"}

        try:
            import win32evtlog          # type: ignore
            import win32evtlogutil      # type: ignore
            import win32con             # type: ignore
            return self._read_events(win32evtlog, win32evtlogutil, win32con,
                                     max_events)
        except ImportError:
            return {
                "available": False,
                "events":    [],
                "reason":    "pywin32 not installed (pip install pywin32)",
            }
        except Exception as exc:
            return {"available": False, "events": [], "reason": str(exc)}

    @staticmethod
    def _read_events(win32evtlog, win32evtlogutil, win32con,
                     max_events: int) -> Dict[str, Any]:
        events = []
        handle = win32evtlog.OpenEventLog(None, "System")
        try:
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            # Event types we care about: ERROR (1) and CRITICAL maps to ERROR
            target_types = {win32con.EVENTLOG_ERROR_TYPE}
            collected = 0
            while collected < max_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for rec in records:
                    if rec.EventType in target_types:
                        try:
                            msg = win32evtlogutil.SafeFormatMessage(rec, "System")
                        except Exception:
                            msg = "(Message unavailable)"
                        events.append({
                            "time":     str(rec.TimeGenerated),
                            "source":   rec.SourceName,
                            "event_id": rec.EventID & 0xFFFF,
                            "type":     "Error",
                            "message":  msg[:200].replace("\r\n", " "),
                        })
                        collected += 1
                        if collected >= max_events:
                            break
        finally:
            win32evtlog.CloseEventLog(handle)

        return {"available": True, "events": events, "reason": ""}


# ─────────────────────────────────────────────────────────────────────────────
# Health Score Engine
# ─────────────────────────────────────────────────────────────────────────────

class HealthScore:
    """
    Calculates an overall system health score from 0 (critical) to 100 (perfect).

    Scoring methodology (inspired by ITIL health KPIs):
      Component          Weight  Thresholds
      ─────────────────  ──────  ─────────────────────────────────────────
      CPU Usage            25%   <60=full, 60-80=partial, >80=0
      Memory Usage         25%   <70=full, 70-85=partial, >85=0
      Disk (worst drive)   30%   <80=full, 80-90=partial, >90=0
      Critical Services    20%   (Windows) each stopped service -5 pts

    Score bands:
      90-100 = Excellent  (green)
      70-89  = Good       (green)
      50-69  = Fair       (yellow)
      25-49  = Poor       (red)
      0-24   = Critical   (red bold)
    """

    def calculate(self, cpu: Dict, memory: Dict, disk: Dict,
                  services: Dict) -> Dict[str, Any]:
        score   = 100.0
        reasons = []

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu_pct = cpu.get("usage_pct", 0)
        if cpu_pct >= 80:
            deduct = 25
            score -= deduct
            reasons.append(f"CPU critical ({cpu_pct:.1f}%) −{deduct}pts")
        elif cpu_pct >= 60:
            deduct = 12
            score -= deduct
            reasons.append(f"CPU elevated ({cpu_pct:.1f}%) −{deduct}pts")

        # ── Memory ────────────────────────────────────────────────────────────
        mem_pct = memory.get("usage_pct", 0)
        if mem_pct >= 85:
            deduct = 25
            score -= deduct
            reasons.append(f"Memory critical ({mem_pct:.1f}%) −{deduct}pts")
        elif mem_pct >= 70:
            deduct = 12
            score -= deduct
            reasons.append(f"Memory elevated ({mem_pct:.1f}%) −{deduct}pts")

        # ── Disk ──────────────────────────────────────────────────────────────
        partitions = disk.get("partitions", [])
        if partitions:
            worst_pct  = max(p.get("usage_pct", 0) for p in partitions)
            worst_name = next(
                (p["mountpoint"] for p in partitions
                 if p.get("usage_pct", 0) == worst_pct), "?"
            )
            if worst_pct >= 95:
                deduct = 30
                score -= deduct
                reasons.append(f"Disk {worst_name} critical ({worst_pct:.1f}%) −{deduct}pts")
            elif worst_pct >= 85:
                deduct = 15
                score -= deduct
                reasons.append(f"Disk {worst_name} full ({worst_pct:.1f}%) −{deduct}pts")
            elif worst_pct >= 70:
                deduct = 5
                score -= deduct
                reasons.append(f"Disk {worst_name} filling ({worst_pct:.1f}%) −{deduct}pts")

        # ── Services (Windows) ────────────────────────────────────────────────
        stopped = services.get("stopped_critical", [])
        if stopped:
            deduct = min(len(stopped) * 5, 20)
            score -= deduct
            names  = ", ".join(s["friendly_name"] for s in stopped[:3])
            reasons.append(f"{len(stopped)} critical service(s) stopped ({names}) −{deduct}pts")

        score = max(0.0, min(100.0, score))
        return {
            "score":   round(score, 1),
            "reasons": reasons,
            "grade":   self._grade(score),
            "color":   self._color(score),
        }

    @staticmethod
    def _grade(score: float) -> str:
        if score >= 90: return "Excellent"
        if score >= 70: return "Good"
        if score >= 50: return "Fair"
        if score >= 25: return "Poor"
        return "Critical"

    @staticmethod
    def _color(score: float) -> str:
        if score >= 70: return "green"
        if score >= 50: return "yellow"
        return "red"


class Recommendations:
    """
    Generates actionable recommendations based on collected metrics.

    Recommendations follow the ITIL/CompTIA A+ troubleshooting model:
      1. Identify the problem
      2. Establish probable cause
      3. Provide a corrective action
    """

    def generate(self, cpu: Dict, memory: Dict, disk: Dict,
                 network: Dict, services: Dict, sysinfo: Dict) -> List[str]:
        recs: List[str] = []

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu_pct = cpu.get("usage_pct", 0)
        if cpu_pct >= 85:
            recs.append(
                f"[HIGH CPU] Usage at {cpu_pct:.1f}% — review top processes, check for "
                "malware or runaway services. Consider adding cores or optimising workloads."
            )
        elif cpu_pct >= 70:
            recs.append(
                f"[ELEVATED CPU] Usage at {cpu_pct:.1f}% — monitor trend. "
                "If sustained, identify heavy processes and schedule off-hours tasks."
            )

        top_cpu = cpu.get("top_processes", [])
        if top_cpu:
            top = top_cpu[0]
            cpu_val = top.get("cpu", 0)
            if isinstance(cpu_val, (int, float)) and cpu_val > 30:
                recs.append(
                    f"[PROCESS] '{top['name']}' (PID {top['pid']}) consuming "
                    f"{cpu_val:.1f}% CPU — investigate or restart if unexpected."
                )

        # ── Memory ────────────────────────────────────────────────────────────
        mem_pct = memory.get("usage_pct", 0)
        if mem_pct >= 90:
            recs.append(
                f"[CRITICAL MEMORY] RAM at {mem_pct:.1f}% — system may become unresponsive. "
                "Close applications, check for memory leaks, or upgrade RAM."
            )
        elif mem_pct >= 75:
            recs.append(
                f"[HIGH MEMORY] RAM at {mem_pct:.1f}% — identify top consumers below "
                "and consider closing idle applications."
            )

        swap_pct = memory.get("swap_pct", 0)
        if swap_pct >= 50:
            recs.append(
                f"[SWAP USAGE] Page file at {swap_pct:.1f}% — high paging indicates "
                "insufficient RAM. Adding physical memory will significantly improve performance."
            )

        # ── Disk ──────────────────────────────────────────────────────────────
        for part in disk.get("partitions", []):
            pct   = part.get("usage_pct", 0)
            mount = part.get("mountpoint", "?")
            free  = human_bytes(part.get("free", 0))
            if pct >= 95:
                recs.append(
                    f"[DISK CRITICAL] {mount} is {pct:.1f}% full ({free} free) — "
                    "IMMEDIATE action required: clear temp files, run Disk Cleanup, "
                    "or move data to another volume."
                )
            elif pct >= 85:
                recs.append(
                    f"[DISK WARNING] {mount} is {pct:.1f}% full ({free} free) — "
                    "run Disk Cleanup, uninstall unused apps, or archive old files."
                )

        # ── Network ───────────────────────────────────────────────────────────
        conn_count = network.get("connection_count", 0)
        if conn_count > 200:
            recs.append(
                f"[NETWORK] {conn_count} active connections detected — unusually high. "
                "Review with 'netstat -an' to check for suspicious activity."
            )

        io = network.get("io_stats", {})
        errin  = io.get("errin",  0)
        errout = io.get("errout", 0)
        if errin + errout > 100:
            recs.append(
                f"[NETWORK ERRORS] {errin+errout} network errors detected — "
                "check cable, NIC health, and switch port. Could indicate hardware fault."
            )

        # ── Services ──────────────────────────────────────────────────────────
        for svc in services.get("stopped_critical", []):
            name = svc.get("friendly_name", svc.get("name", "?"))
            svc_name = svc.get("name", "")
            recs.append(
                f"[SERVICE STOPPED] '{name}' is not running — "
                f"start it with: sc start {svc_name}  "
                f"If it fails to start, check Event Viewer for details."
            )

        # ── Uptime ────────────────────────────────────────────────────────────
        uptime_s = sysinfo.get("uptime_seconds", 0)
        if uptime_s > 30 * 86400:  # 30 days
            days = uptime_s // 86400
            recs.append(
                f"[UPTIME] System has been running for {days} days without a reboot — "
                "a restart is recommended to apply pending updates and clear memory fragmentation."
            )

        if not recs:
            recs.append("[ALL CLEAR] No significant issues detected. System appears healthy.")

        return recs


# ─────────────────────────────────────────────────────────────────────────────
# Report Renderer
# ─────────────────────────────────────────────────────────────────────────────

class ReportRenderer:
    """
    Renders the collected data into human-readable, JSON, or CSV formats.
    Colors are disabled automatically when writing to a file.
    """

    def __init__(self, json_mode: bool = False, plain: bool = False):
        self.json_mode = json_mode
        if plain or json_mode:
            Color.disable()

    def render(self, data: Dict[str, Any], full: bool = False) -> str:
        if self.json_mode:
            return json.dumps(data, indent=2, default=str)
        return self._render_text(data, full)

    def _render_text(self, data: Dict[str, Any], full: bool) -> str:
        lines: List[str] = []
        now   = datetime.datetime.now()

        # ── Header ────────────────────────────────────────────────────────────
        lines.append(Color.bold(Color.cyan(
            "╔══════════════════════════════════════════════════════════════════════╗"
        )))
        lines.append(Color.bold(Color.cyan(
            "║            SYSTEM HEALTH MONITOR — IT Help Desk Toolkit             ║"
        )))
        lines.append(Color.bold(Color.cyan(
            "╚══════════════════════════════════════════════════════════════════════╝"
        )))
        lines.append(Color.dim(f"  Report generated: {fmt_timestamp(now)}"))
        if not HAS_PSUTIL:
            lines.append(Color.yellow(
                "  [INFO] psutil not found — using fallback collectors "
                "(pip install psutil for richer data)"
            ))

        # ── System Info ───────────────────────────────────────────────────────
        si = data.get("system_info", {})
        lines.append(section_header("SYSTEM INFORMATION"))
        lines.append(f"  Hostname   : {Color.bold(si.get('hostname', 'N/A'))}")
        lines.append(f"  FQDN       : {si.get('fqdn', 'N/A')}")
        lines.append(f"  OS         : {si.get('platform', '?')} {si.get('os_release', '')} "
                     f"({si.get('os_version', '')})")
        lines.append(f"  Machine    : {si.get('machine', 'N/A')}  |  "
                     f"Processor: {si.get('processor', 'N/A')[:60]}")
        lines.append(f"  Boot Time  : {si.get('boot_time', 'N/A')}")
        lines.append(f"  Uptime     : {Color.bold(si.get('uptime_human', 'N/A'))}")
        lines.append(f"  Python     : {si.get('python', 'N/A')}")

        # ── Health Score ──────────────────────────────────────────────────────
        hs = data.get("health_score", {})
        score  = hs.get("score", 0)
        grade  = hs.get("grade", "Unknown")
        clr    = hs.get("color", "white")
        color_fn = {"green": Color.green, "yellow": Color.yellow, "red": Color.red}.get(
            clr, Color.white
        )
        lines.append(section_header("OVERALL HEALTH SCORE"))
        lines.append(
            f"  Score : {color_fn(Color.bold(f'{score:.1f}/100'))}  "
            f"({color_fn(grade)})"
        )
        lines.append(f"  {progress_bar(score, 100, width=40, warn=50, crit=25)}")
        for reason in hs.get("reasons", []):
            lines.append(f"    {Color.yellow('•')} {reason}")

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu = data.get("cpu", {})
        lines.append(section_header("CPU"))
        lines.append(
            f"  Usage    : {progress_bar(cpu.get('usage_pct', 0))}"
        )
        lines.append(
            f"  Cores    : {cpu.get('core_count', '?')} physical / "
            f"{cpu.get('logical_count', '?')} logical"
        )
        freq_cur = cpu.get("freq_current", 0)
        freq_max = cpu.get("freq_max", 0)
        if freq_cur:
            lines.append(f"  Frequency: {freq_cur:.0f} MHz current / {freq_max:.0f} MHz max")
        if full and cpu.get("top_processes"):
            lines.append(f"  {Color.bold('Top CPU Processes:')}")
            for p in cpu["top_processes"]:
                cpu_val = p.get("cpu", 0)
                cpu_str = f"{cpu_val:.1f}%" if isinstance(cpu_val, float) else "N/A"
                lines.append(
                    f"    [{p.get('pid', '?'):>6}] {p.get('name', '?'):<35} "
                    f"CPU: {cpu_str}"
                )

        # ── Memory ────────────────────────────────────────────────────────────
        mem = data.get("memory", {})
        lines.append(section_header("MEMORY (RAM)"))
        lines.append(
            f"  Usage    : {progress_bar(mem.get('usage_pct', 0))}"
        )
        lines.append(
            f"  Total    : {human_bytes(mem.get('total', 0))}  |  "
            f"Used: {human_bytes(mem.get('used', 0))}  |  "
            f"Free: {human_bytes(mem.get('available', 0))}"
        )
        swap_total = mem.get("swap_total", 0)
        if swap_total:
            lines.append(
                f"  Swap/Page: {progress_bar(mem.get('swap_pct', 0))}  "
                f"({human_bytes(mem.get('swap_used', 0))} / "
                f"{human_bytes(swap_total)})"
            )
        if full and mem.get("top_processes"):
            lines.append(f"  {Color.bold('Top Memory Processes:')}")
            for p in mem["top_processes"]:
                mem_b   = p.get("mem_b",  0)
                mem_pct = p.get("mem_pct", 0)
                mem_str = human_bytes(mem_b) if mem_b else f"{mem_pct:.1f}%"
                lines.append(
                    f"    [{p.get('pid', '?'):>6}] {p.get('name', '?'):<35} "
                    f"Mem: {mem_str}"
                )

        # ── Disk ──────────────────────────────────────────────────────────────
        disk = data.get("disk", {})
        lines.append(section_header("DISK"))
        for part in disk.get("partitions", []):
            pct    = part.get("usage_pct", 0)
            status = part.get("status", "OK")
            flag   = ""
            if status == "CRITICAL":
                flag = f"  {Color.red('[CRITICAL — IMMEDIATE ACTION]')}"
            elif status == "WARNING":
                flag = f"  {Color.yellow('[WARNING — >85% Full]')}"
            lines.append(
                f"  {Color.bold(part.get('mountpoint', '?'))} "
                f"({part.get('fstype', '?')}){flag}"
            )
            lines.append(f"    {progress_bar(pct)}")
            lines.append(
                f"    Total: {human_bytes(part.get('total', 0))}  |  "
                f"Used: {human_bytes(part.get('used', 0))}  |  "
                f"Free: {human_bytes(part.get('free', 0))}"
            )
        io = disk.get("io_stats", {})
        if io and full:
            lines.append(
                f"  I/O Totals: Read {human_bytes(io.get('read_bytes',0))}  "
                f"Write {human_bytes(io.get('write_bytes',0))}  "
                f"({io.get('read_count',0):,} reads / {io.get('write_count',0):,} writes)"
            )

        # ── Network ───────────────────────────────────────────────────────────
        net = data.get("network", {})
        lines.append(section_header("NETWORK"))
        lines.append(f"  Active Connections: {Color.bold(str(net.get('connection_count', 0)))}")
        net_io = net.get("io_stats", {})
        if net_io:
            lines.append(
                f"  Bytes Received : {human_bytes(net_io.get('bytes_recv', 0))}  "
                f"({net_io.get('packets_recv', 0):,} packets)"
            )
            lines.append(
                f"  Bytes Sent     : {human_bytes(net_io.get('bytes_sent', 0))}  "
                f"({net_io.get('packets_sent', 0):,} packets)"
            )
            errs = net_io.get("errin", 0) + net_io.get("errout", 0)
            if errs:
                lines.append(Color.yellow(f"  Network Errors : {errs}"))
        if full:
            for iface in net.get("interfaces", []):
                status_str = Color.green("UP") if iface.get("is_up") else Color.red("DOWN")
                lines.append(
                    f"  [{status_str}] {Color.bold(iface.get('name', '?'))}"
                    f"  MAC: {iface.get('mac', 'N/A')}"
                    + (f"  Speed: {iface.get('speed', 0)} Mbps" if iface.get("speed") else "")
                )
                for ip in iface.get("ipv4", []):
                    lines.append(f"         IPv4: {ip}")
                for ip in iface.get("ipv6", []):
                    lines.append(f"         IPv6: {ip[:40]}")

        # ── Services ──────────────────────────────────────────────────────────
        svc = data.get("services", {})
        if svc.get("available"):
            lines.append(section_header("CRITICAL WINDOWS SERVICES"))
            for s in svc.get("services", []):
                state = s.get("state", "Unknown")
                if state == "Running":
                    state_str = Color.green(f"{'Running':15}")
                else:
                    state_str = Color.red(f"{state:15}")
                lines.append(
                    f"  {state_str} {s.get('friendly_name', s.get('name', '?'))}"
                )
        elif IS_WINDOWS and not svc.get("available"):
            lines.append(section_header("CRITICAL WINDOWS SERVICES"))
            lines.append(Color.dim("  Service query unavailable."))

        # ── Event Log ─────────────────────────────────────────────────────────
        evts = data.get("event_log", {})
        if full:
            lines.append(section_header("EVENT LOG — Recent Errors (System)"))
            if evts.get("available"):
                for e in evts.get("events", []):
                    lines.append(
                        f"  {Color.yellow(e.get('time','?')[:19])}  "
                        f"EventID {Color.bold(str(e.get('event_id','?')))}  "
                        f"Source: {e.get('source','?')}"
                    )
                    lines.append(Color.dim(f"    {e.get('message','')[:120]}"))
                if not evts.get("events"):
                    lines.append(Color.green("  No error events found in System log."))
            else:
                lines.append(Color.dim(f"  Unavailable: {evts.get('reason', 'N/A')}"))

        # ── Recommendations ───────────────────────────────────────────────────
        lines.append(section_header("RECOMMENDATIONS"))
        for rec in data.get("recommendations", []):
            if rec.startswith("[ALL CLEAR]"):
                lines.append(f"  {Color.green('✔')} {Color.green(rec)}")
            elif "CRITICAL" in rec or "STOPPED" in rec:
                lines.append(f"  {Color.red('!')} {Color.red(rec)}")
            elif "WARNING" in rec or "HIGH" in rec or "ELEVATED" in rec:
                lines.append(f"  {Color.yellow('▲')} {Color.yellow(rec)}")
            else:
                lines.append(f"  {Color.cyan('•')} {rec}")

        lines.append("\n" + Color.dim("─" * 70))
        lines.append(Color.dim(f"  End of report — {fmt_timestamp(now)}"))
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def render_csv(data: Dict[str, Any]) -> str:
        """Flatten key metrics into CSV rows suitable for logging/trending."""
        import io as _io
        buf = _io.StringIO()
        writer = csv.writer(buf)
        now = datetime.datetime.now().isoformat()

        writer.writerow(["timestamp", "metric", "value", "unit"])

        si = data.get("system_info", {})
        writer.writerow([now, "hostname",       si.get("hostname", ""),       ""])
        writer.writerow([now, "os",             si.get("os_version", ""),     ""])
        writer.writerow([now, "uptime_seconds", si.get("uptime_seconds", 0),  "seconds"])
        writer.writerow([now, "boot_time",      si.get("boot_time", ""),      ""])

        cpu = data.get("cpu", {})
        writer.writerow([now, "cpu_usage_pct",    cpu.get("usage_pct", 0),     "%"])
        writer.writerow([now, "cpu_cores",        cpu.get("core_count", 0),    "cores"])
        writer.writerow([now, "cpu_freq_mhz",     cpu.get("freq_current", 0),  "MHz"])

        mem = data.get("memory", {})
        writer.writerow([now, "mem_total_bytes",  mem.get("total", 0),         "bytes"])
        writer.writerow([now, "mem_used_bytes",   mem.get("used",  0),         "bytes"])
        writer.writerow([now, "mem_usage_pct",    mem.get("usage_pct", 0),     "%"])
        writer.writerow([now, "swap_usage_pct",   mem.get("swap_pct", 0),      "%"])

        for part in data.get("disk", {}).get("partitions", []):
            mp = part.get("mountpoint", "?").replace(",", "_")
            writer.writerow([now, f"disk_{mp}_total",  part.get("total", 0),      "bytes"])
            writer.writerow([now, f"disk_{mp}_used",   part.get("used",  0),      "bytes"])
            writer.writerow([now, f"disk_{mp}_pct",    part.get("usage_pct", 0),  "%"])

        net = data.get("network", {})
        nio = net.get("io_stats", {})
        writer.writerow([now, "net_bytes_sent",   nio.get("bytes_sent", 0),    "bytes"])
        writer.writerow([now, "net_bytes_recv",   nio.get("bytes_recv", 0),    "bytes"])
        writer.writerow([now, "net_connections",  net.get("connection_count", 0), "count"])

        writer.writerow([now, "health_score",     data.get("health_score", {}).get("score", 0), "pts"])

        return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Data Collection Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class SystemHealthMonitor:
    """
    Orchestrates all data collection classes and builds the final data payload.
    Collection runs in parallel threads where safe to do so, reducing total
    wall-clock time from ~10s to ~3s on a typical Windows system.
    """

    def collect_all(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        errors:  Dict[str, str] = {}

        def run(key: str, fn):
            try:
                results[key] = fn()
            except Exception as exc:
                errors[key]  = str(exc)
                results[key] = {}

        # Threads for independent collectors
        threads = [
            threading.Thread(target=run, args=("system_info", SystemInfo().collect),  daemon=True),
            threading.Thread(target=run, args=("cpu",         CPUInfo().collect),      daemon=True),
            threading.Thread(target=run, args=("memory",      MemoryInfo().collect),   daemon=True),
            threading.Thread(target=run, args=("disk",        DiskInfo().collect),     daemon=True),
            threading.Thread(target=run, args=("network",     NetworkInfo().collect),  daemon=True),
            threading.Thread(target=run, args=("services",    ServicesInfo().collect), daemon=True),
            threading.Thread(target=run, args=("event_log",   EventLogInfo().collect), daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45)   # Don't block forever if a collector hangs

        # Dependent calculations (require collected data)
        hs_engine = HealthScore()
        results["health_score"] = hs_engine.calculate(
            results.get("cpu",      {}),
            results.get("memory",   {}),
            results.get("disk",     {}),
            results.get("services", {}),
        )

        rec_engine = Recommendations()
        results["recommendations"] = rec_engine.generate(
            results.get("cpu",         {}),
            results.get("memory",      {}),
            results.get("disk",        {}),
            results.get("network",     {}),
            results.get("services",    {}),
            results.get("system_info", {}),
        )

        if errors:
            results["_collection_errors"] = errors

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Output Saving
# ─────────────────────────────────────────────────────────────────────────────

def save_report(content: str, path: str, is_csv: bool = False) -> None:
    """Write the rendered report to disk, creating parent directories as needed."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="" if is_csv else "\n") as f:
        f.write(content)
    print(Color.green(f"\n  Report saved → {os.path.abspath(path)}"))


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="system_health.py",
        description=(
            "System Health Monitor — IT Help Desk / Cybersecurity Portfolio Tool\n"
            "Collects CPU, memory, disk, network, services, and event log data,\n"
            "calculates a health score, and provides actionable recommendations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python system_health.py                  # Quick summary\n"
            "  python system_health.py --full           # All sections\n"
            "  python system_health.py --json           # JSON output\n"
            "  python system_health.py --output out.txt # Save to text file\n"
            "  python system_health.py --output out.csv # Save to CSV log\n"
            "  python system_health.py --watch 5        # Refresh every 5 s\n"
            "  python system_health.py --full --watch 10 --output health.txt\n"
        ),
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Include all sections (top processes, interfaces, event log, I/O stats)"
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output raw data as JSON (useful for piping to jq or SIEM tools)"
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Save report to .txt (human-readable) or .csv (metrics log)"
    )
    parser.add_argument(
        "--watch", metavar="SECONDS", type=int, default=0,
        help="Auto-refresh every N seconds (0 = run once)"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color output (useful for redirected output)"
    )
    return parser


def run_once(args: argparse.Namespace) -> None:
    """Collect data, render, print, and optionally save — one iteration."""
    monitor  = SystemHealthMonitor()
    data     = monitor.collect_all()

    is_csv   = bool(args.output and args.output.lower().endswith(".csv"))
    plain    = args.no_color or bool(args.output)     # plain text when saving
    renderer = ReportRenderer(json_mode=args.json_output, plain=plain)

    if args.json_output:
        output = renderer.render(data, full=args.full)
        print(output)
        if args.output:
            save_report(output, args.output)
        return

    if is_csv and args.output:
        csv_content = renderer.render_csv(data)
        # Append if file exists (useful for --watch trending)
        header_needed = not os.path.exists(args.output)
        with open(args.output, "a", encoding="utf-8", newline="") as f:
            if header_needed:
                f.write(csv_content)
            else:
                # Skip header row (first line) when appending
                lines = csv_content.splitlines()
                f.write("\n".join(lines[1:]) + "\n")
        # Still print human-readable to console
        console_renderer = ReportRenderer(json_mode=False, plain=False)
        print(console_renderer.render(data, full=args.full))
        print(Color.green(f"\n  CSV row appended → {os.path.abspath(args.output)}"))
        return

    # Standard text render — always print to console
    console_renderer = ReportRenderer(json_mode=False, plain=False)
    print(console_renderer.render(data, full=args.full))

    if args.output:
        # Save plain (no ANSI) version to file
        file_renderer = ReportRenderer(json_mode=False, plain=True)
        save_report(file_renderer.render(data, full=args.full), args.output)


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color:
        Color.disable()

    if args.watch > 0:
        iteration = 0
        try:
            while True:
                if iteration > 0:
                    # Clear screen between refreshes for a dashboard feel
                    os.system("cls" if IS_WINDOWS else "clear")
                print(Color.dim(
                    f"  Auto-refresh every {args.watch}s "
                    f"— press Ctrl+C to stop (iteration {iteration + 1})"
                ))
                run_once(args)
                iteration += 1
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print(Color.cyan("\n\n  Monitoring stopped. Goodbye."))
    else:
        run_once(args)


if __name__ == "__main__":
    main()
