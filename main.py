"""crowdstrike-sysinfo — what each fleet host actually is, over RTR.

OS and build, serial numbers, CPU, memory down to the DIMM, disks, firmware and
uptime. The msinfo32 answer, for every host at once.

It owns no credentials. Auth and the host list come from the ``crowdstrike``
capability; this module only knows how to ask a host about itself.

Why ask the host
----------------
Falcon's inventory knows a host's OS and its own serial for the agent. It does
not know which DIMM slots are filled, what the BIOS version is, whether Secure
Boot is on, or what the board's serial is — and those are the questions asked
when a machine is being replaced, audited, or explained.

An RTR session **per host** and one ``runscript`` per pass. One session per host
rather than one batch across many is the point of the screen: a batch returns
when its slowest member does, while here each host lands on its own and can be
opened while the rest are still going.

Read-only: inventory tables are read and nothing is changed.

What it reads
-------------
* **Windows**, in two passes — `Win32_ComputerSystem`, `…Product`,
  `…OperatingSystem`, `BIOS` and `BaseBoard` first; then `Processor`,
  `PhysicalMemory`, `DiskDrive` and `VideoController`. Split so that a host which
  refuses or times out on the slower hardware walk still returns its OS and
  serial, which is most of what anyone asks for.
* **Linux** — DMI under ``/sys/class/dmi/id`` for the serials (root-only, which
  RTR is), ``/etc/os-release``, ``/proc``, and ``dmidecode`` for per-DIMM detail
  where it is installed.
* **macOS** — ``system_profiler``, ``sw_vers`` and ``sysctl``.

A fact is ``section | item | value`` rather than a row of a table, because this
answers *what is this machine* rather than *what does it have many of*.

Methods
-------
  ui              -> the screen: fetch hosts, tick them, scan
  fetch           -> load the reachable inventory from ``crowdstrike``
  scan_selected   -> read the ticked hosts
  scan_all        -> read every listed host
  progress        -> one tick of the progress loop
  stop            -> call off what has not started
  open_host       -> one host's facts, in a tab (the double-click target)
  sysinfo         -> the same data as JSON, for other modules
  read_host       -> read one host on request, for the host panel
"""

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from limen_sdk import (
    Button,
    Catalog,
    Checkbox,
    Label,
    MenuItem,
    Module,
    Row,
    Separator,
    Table,
    Text,
    Window,
)

# The module's own strings. `host.locale()` is asked per render rather than
# once at start: the language is the application's setting and can change
# while the module is running.
CAT = Catalog.from_dir(os.path.dirname(os.path.abspath(__file__)), ("en", "uk"))
_lang = {"code": "en"}


def t(key, **args):
    """Translate for the language the host last reported."""
    return CAT.tr(_lang["code"], key, **args)


def _sync_locale():
    """Re-read the host's language before drawing.

    Asked each time rather than once at start, because it is the
    application's setting and the user can change it while the module is
    open. One round-trip per render, which is what the Rust modules do too.
    """
    try:
        _lang["code"] = m.host.locale()
    except Exception:  # noqa: BLE001
        pass  # keep the last language rather than failing to draw


CAP = "crowdstrike.sysinfo"
m = Module("crowdstrike-sysinfo", [CAP])

# The fetched inventory. Held so reopening the tab restores the list rather than
# re-querying the fleet.
_hosts = {"rows": None}
_status = {"msg": ""}

# Per-host scan state, the only thing shared between the worker threads and the
# dispatch thread — so every read and write of it takes `_lock`.
#
#   _jobs[host_id] = {hostname, platform, state, facts, error, notes}
#   state: "queued" | "scanning" | "done" | "failed" | "stopped"
_jobs = {}
_lock = threading.Lock()

# One-host reads asked for by another module — the host panel — by device id.
# Kept apart from `_jobs`: asking about one machine must neither wipe what the
# fleet screen is showing nor wait for a fleet scan to finish. Same lock.
_reads = {}

# Workers must not log through `host`: the SDK's host bridge writes a frame to
# stdout and then reads stdin, and that is the JSON-RPC pipe. A second thread
# using it interleaves a write into the protocol and steals a line of the
# response. So workers put their lines here and the dispatch thread drains them
# on the next poll, where logging is safe.
_logq = queue.Queue()

# The running scan: the pool doing the work, and the flag that calls it off.
_run = {"pool": None, "stop": None, "started": 0.0}

# One host at a time per thread, and few enough threads not to be rate-limited
# off the Falcon API — the aim is that a small fleet finishes quickly, not that a
# large one arrives all at once.
MAX_WORKERS = 8

# A scan of a large fleet returns a lot of rows, and every one of them crosses
# the RTR response, this process, and the UI — so there is a cap per host.
#
# Set far higher than the device list's, because the shape of the data is
# different: a host has a handful of physical interfaces and can have hundreds of
# virtual ones — container veths, tunnels, VPN adapters — and on a container host
# that is the whole list. Generous enough that the cap is a guard rather than a
# limit, and when it does bite the host says so on its own row.
MAX_ROWS_PER_HOST = 5000

# How long the script itself may run on the endpoint. Falcon caps this at 600.
RTR_TIMEOUT = 600

# The most one `runscript -Raw` may carry. The command travels as a single string
# in a REST body, and the figures quoted for RTR sit around 4 KB — so this is set
# below that and enforced when the script is built, where it is a loud failure in
# a test, rather than discovered on a host as empty output.
MAX_SCRIPT_BYTES = 4000

# How long a poll waits before answering. The host re-invokes an `auto` action as
# soon as the view renders, so without this the progress loop would spin as fast
# as the two processes can exchange frames, for as long as the scan lasts.
POLL_SECONDS = 0.6


class _Stopped(Exception):
    """Raised inside a worker when Stop was pressed — a cancellation, not a
    failure, and shown as one."""


class _UnknownOS(Exception):
    """The host's OS is not one this module can read, so nothing is run on it."""

    def __init__(self, platform):
        super().__init__(f"unsupported OS: {platform}")
        self.platform = platform


# --------------------------------------------------------------------------- #
# Falcon RTR (auth and the inventory come from the crowdstrike capability).
# --------------------------------------------------------------------------- #
def _http(method, url, token, body=None):
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    # Walking three registry views (or four package databases) takes longer
    # than a notification does, so the read timeout is generous.
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, (json.loads(raw) if raw else {})


def _auth(host):
    """Bearer token + API base from the crowdstrike capability."""
    token = (host.call("crowdstrike", "token", {}) or {}).get("token")
    base = (
        (host.call("crowdstrike", "api", {}) or {})
        .get("base_url", "https://api.crowdstrike.com")
        .rstrip("/")
    )
    if not token:
        raise RuntimeError(
            "no CrowdStrike token — configure the crowdstrike module first"
        )
    return token, base


def _rtr_one(hid, platform, token, base, stop):
    """Enumerate ONE host and return its stdout.

    One RTR session per host rather than one batch across many: a batch returns
    when its slowest member does, and this module's whole point is that a finished
    host is usable while the others are still going. The cost is an init call per
    host, which is what the thread pool is for.

    Raises on failure — the caller turns that into the host's error state. Never
    touches `host`: this runs on a worker thread, and the SDK's host bridge is the
    JSON-RPC pipe on stdio, which only the dispatch thread may write to.
    """
    if stop.is_set():
        raise _Stopped()
    # Chosen first, so a host whose OS we cannot read costs no RTR session and
    # nothing is run on it.
    passes = _script_for(platform)
    st, init = _http(
        "POST",
        f"{base}/real-time-response/combined/batch-init-session/v1",
        token,
        {"host_ids": [hid], "timeout": 120},
    )
    batch_id = init.get("batch_id")
    if not batch_id:
        raise RuntimeError(f"no RTR session (RTR enabled for this host?) HTTP {st}")
    resources = init.get("resources") or {}
    if isinstance(resources, dict):
        for r in resources.values():
            for e in r.get("errors") or []:
                raise RuntimeError(str(e.get("message", e)))

    # One session, then each pass over it. Their outputs are concatenated: the
    # parser only ever sees lines, so it neither knows nor needs to know that they
    # arrived in several pieces.
    collected, troubles = [], []
    for label, script in passes:
        if stop.is_set():
            raise _Stopped()
        # `-Timeout` before `-Raw`: the raw block ends at a fence, and anything
        # after that fence is ambiguous, so no argument goes there.
        command_string = f"runscript -Timeout={RTR_TIMEOUT} -Raw=```" + script + "```"
        st, res = _http(
            "POST",
            f"{base}/real-time-response/combined/batch-admin-command/v1",
            token,
            {
                "batch_id": batch_id,
                "base_command": "runscript",
                "command_string": command_string,
            },
        )
        per_host = (res.get("combined", {}).get("resources", {}) or {}).get(hid)
        if per_host is None:
            troubles.append(f"{label}: no answer (HTTP {st})")
            continue
        stdout = per_host.get("stdout") or ""
        if "#begin" in stdout:
            collected.append(stdout)
            continue
        # The script prints `#begin` before doing anything, so its absence does
        # not mean "nothing here" — it means the pass did not run. One pass
        # failing is not the host failing, so it is recorded and the rest go on.
        stderr = (per_host.get("stderr") or "").strip()
        errs = "; ".join(str(e.get("message", e)) for e in per_host.get("errors") or [])
        troubles.append(f"{label}: {errs or stderr or 'did not run'}")

    if not collected:
        # Every pass failed, so there is nothing to show and a reason to give.
        raise RuntimeError("; ".join(troubles) or "the script did not run on this host")
    if troubles:
        # Some of the picture is missing, and the operator has to know which part
        # rather than be handed a short list that looks complete.
        collected.append("#err=" + "; ".join(troubles) + "\n")
    return "\n".join(collected)


# --------------------------------------------------------------------------- #
# The enumeration scripts.
#
# Each prints one entry per line as
#     section|item|value
# plus `#`-prefixed metadata lines. A flat line format rather than JSON on
# purpose: RTR hands back stdout as loose text and truncates it, and a truncated
# JSON document is worth nothing while a truncated list of lines is worth all but
# the last line.
#
# **No backticks.** The script is sent inside an RTR ```...``` block, and a
# backtick is also PowerShell's escape character — one in here corrupts the
# command on the wire, so the Windows script escapes nothing and quotes with
# single quotes throughout.
# --------------------------------------------------------------------------- #

# Windows, in two passes: what the machine *is*, then what is *in* it.
#
# Split because the second half is the slow one — a host that refuses or times
# out on the hardware walk still returns its OS and serial, which is most of what
# anyone asks for — and because one script covering both crowds what a
# `runscript -Raw` command can carry.
_WIN_PRE = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Say($section, $key, $value) {
  $v = Clean $value
  if (-not $v) { return }
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output ($section + '|' + (Clean $key) + '|' + $v)
}
function GB($bytes) {
  if (-not $bytes) { return '' }
  return ('{0:N1} GB' -f ($bytes / 1GB))
}
"""

_WIN_SYSTEM = _WIN_PRE + r"""
try {
$cs = Get-CimInstance Win32_ComputerSystem
$csp = Get-CimInstance Win32_ComputerSystemProduct
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$bb = Get-CimInstance Win32_BaseBoard
Say 'system' 'Manufacturer' $cs.Manufacturer
Say 'system' 'Model' $cs.Model
Say 'system' 'Serial number' $csp.IdentifyingNumber
Say 'system' 'UUID' $csp.UUID
Say 'system' 'Domain' $cs.Domain
Say 'system' 'Logged in' $cs.UserName
Say 'system' 'Memory installed' (GB $cs.TotalPhysicalMemory)
Say 'os' 'Name' $os.Caption
Say 'os' 'Version' ($os.Version + ' build ' + $os.BuildNumber)
Say 'os' 'Architecture' $os.OSArchitecture
Say 'os' 'System drive' $os.SystemDrive
if ($os.InstallDate) { Say 'os' 'Installed' $os.InstallDate.ToString('yyyy-MM-dd HH:mm') }
if ($os.LastBootUpTime) {
  Say 'os' 'Last boot' $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
  $up = (Get-Date) - $os.LastBootUpTime
  Say 'os' 'Uptime' ('{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes)
}
Say 'firmware' 'BIOS vendor' $bios.Manufacturer
Say 'firmware' 'BIOS version' $bios.SMBIOSBIOSVersion
Say 'firmware' 'BIOS serial' $bios.SerialNumber
Say 'firmware' 'Board' ((Clean $bb.Manufacturer) + ' ' + (Clean $bb.Product))
Say 'firmware' 'Board serial' $bb.SerialNumber
$sb = Confirm-SecureBootUEFI
if ($null -ne $sb) { Say 'firmware' 'Secure Boot' $sb }
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

_WIN_HARDWARE = _WIN_PRE + r"""
try {
foreach ($c in @(Get-CimInstance Win32_Processor)) {
  Say 'cpu' 'Model' $c.Name
  Say 'cpu' 'Socket' $c.SocketDesignation
  Say 'cpu' 'Cores' ((Clean $c.NumberOfCores) + ' physical, ' + (Clean $c.NumberOfLogicalProcessors) + ' logical')
  Say 'cpu' 'Max clock' ((Clean $c.MaxClockSpeed) + ' MHz')
}
foreach ($m in @(Get-CimInstance Win32_PhysicalMemory)) {
  $what = (GB $m.Capacity)
  if ($m.Speed) { $what = $what + ' @ ' + (Clean $m.Speed) + ' MHz' }
  if ($m.Manufacturer) { $what = $what + ' ' + (Clean $m.Manufacturer) }
  if ($m.PartNumber) { $what = $what + ' ' + (Clean $m.PartNumber) }
  if ($m.SerialNumber) { $what = $what + ' SN ' + (Clean $m.SerialNumber) }
  Say 'memory' (Clean $m.DeviceLocator) $what
}
foreach ($d in @(Get-CimInstance Win32_DiskDrive)) {
  $what = (Clean $d.Model) + ' ' + (GB $d.Size)
  if ($d.SerialNumber) { $what = $what + ' SN ' + (Clean $d.SerialNumber) }
  if ($d.InterfaceType) { $what = $what + ' (' + (Clean $d.InterfaceType) + ')' }
  Say 'disk' (Clean $d.DeviceID) $what
}
foreach ($g in @(Get-CimInstance Win32_VideoController)) {
  Say 'display' (Clean $g.Name) ('driver ' + (Clean $g.DriverVersion))
  Say 'about' 'gpu' $g.Name
}
# Device specifications, as Settings shows them. Raw values only: the module
# formats them in the user's language, and Windows translates its own words.
Say 'about' 'name' $env:COMPUTERNAME
$p = @(Get-CimInstance Win32_Processor)[0]
Say 'about' 'cpu' $p.Name
Say 'about' 'cpu_arch' $p.Architecture
$mhz = (Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0').'~MHz'
if (-not $mhz) { $mhz = $p.MaxClockSpeed }
Say 'about' 'cpu_mhz' $mhz
$ram = 0.0
foreach ($m in @(Get-CimInstance Win32_PhysicalMemory)) { $ram += [double]$m.Capacity }
Say 'about' 'ram_installed' $ram
Say 'about' 'ram_usable' (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
$size = 0.0; $free = 0.0
foreach ($v in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) { $size += [double]$v.Size; $free += [double]$v.FreeSpace }
Say 'about' 'disk_size' $size
Say 'about' 'disk_free' $free
Say 'about' 'device_id' (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SQMClient').MachineId
Say 'about' 'product_id' (Get-CimInstance Win32_OperatingSystem).SerialNumber
Say 'about' 'os64' ([Environment]::Is64BitOperatingSystem)
# Touch and pen by HID usage (digitizer page 0D: 04 touch screen, 02 pen), not
# by device name, which Windows translates.
$touch = 0; $pen = 0
foreach ($h in @(Get-CimInstance Win32_PnPEntity -Filter 'PNPClass=''HIDClass''')) {
  $ids = (@($h.CompatibleID) + @($h.HardwareID)) -join ' '
  if ($ids -match 'UP:000D_U:0004') { $touch++ }
  if ($ids -match 'UP:000D_U:0002') { $pen++ }
}
Say 'about' 'touch' $touch
Say 'about' 'pen' $pen
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""
# Linux. DMI is where the serial numbers live and it is root-only — which RTR is,
# so this reads what an unprivileged tool could not.
_LINUX = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
n=0
say() {
  # sysfs pads model strings to a fixed width, so runs of spaces are squeezed and
  # the ends trimmed — once here rather than in every line that builds a value.
  v=$(printf '%s' "$3" | tr -d '|' | tr '\n' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')
  [ -n "$v" ] || return 0
  n=$((n+1))
  if [ "$n" -gt "$LIMIT" ]; then echo '#truncated'; exit 0; fi
  printf '%s|%s|%s\n' "$1" "$2" "$v"
}
dmi() { cat "/sys/class/dmi/id/$1" 2>/dev/null; }
# DMI holds the serials and is root-only. RTR runs as root, so this normally
# reads — but if it ever does not, an absent serial must not look like a machine
# that has none.
[ -r /sys/class/dmi/id/product_serial ] || echo '#no-dmi'
say system 'Manufacturer' "$(dmi sys_vendor)"
say system 'Model' "$(dmi product_name)"
say system 'Serial number' "$(dmi product_serial)"
say system 'UUID' "$(dmi product_uuid)"
say system 'Hostname' "$(cat /proc/sys/kernel/hostname 2>/dev/null)"
. /etc/os-release 2>/dev/null
say os 'Name' "$PRETTY_NAME"
say os 'Version' "$VERSION_ID"
say os 'Kernel' "$(uname -sr)"
say os 'Architecture' "$(uname -m)"
up=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
[ -n "$up" ] && say os 'Uptime' "$((up/86400))d $(((up%86400)/3600))h $(((up%3600)/60))m"
say os 'Booted' "$(uptime -s 2>/dev/null)"
say cpu 'Model' "$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
say cpu 'Cores' "$(awk '/^processor/{n++} END{if (n) print n " logical"}' /proc/cpuinfo 2>/dev/null)"
say memory 'Total' "$(awk '/^MemTotal/{printf "%.1f GB", $2/1048576}' /proc/meminfo 2>/dev/null)"
# Per DIMM needs dmidecode, which is not always installed. The total above always
# is, so its absence costs a detail rather than the answer.
if command -v dmidecode >/dev/null 2>&1; then
  dmidecode -t memory 2>/dev/null | awk '
    /^Memory Device/ { loc=""; sz=""; sp=""; mf=""; pn=""; sn=""; inblk=1; next }
    inblk && /Locator:/ && !/Bank Locator/ { sub(/^[ \t]*Locator:[ \t]*/, ""); loc=$0 }
    inblk && /Size:/ { sub(/^[ \t]*Size:[ \t]*/, ""); sz=$0 }
    inblk && /Speed:/ && !/Configured/ { sub(/^[ \t]*Speed:[ \t]*/, ""); sp=$0 }
    inblk && /Manufacturer:/ { sub(/^[ \t]*Manufacturer:[ \t]*/, ""); mf=$0 }
    inblk && /Part Number:/ { sub(/^[ \t]*Part Number:[ \t]*/, ""); pn=$0 }
    inblk && /Serial Number:/ { sub(/^[ \t]*Serial Number:[ \t]*/, ""); sn=$0 }
    /^$/ {
      if (inblk && loc != "" && sz != "" && sz !~ /No Module/) {
        gsub(/\|/, " ", loc); gsub(/\|/, " ", pn); gsub(/\|/, " ", mf)
        print "memory|" loc "|" sz " @ " sp " " mf " " pn " SN " sn
      }
      inblk=0
    }'
fi
for d in /sys/block/*/ ; do
  b=$(basename "$d")
  case "$b" in loop*|ram*|zram*|dm-*|sr*) continue ;; esac
  sz=$(awk -v s="$(cat "$d/size" 2>/dev/null)" 'BEGIN{ if (s) printf "%.1f GB", s*512/1073741824 }')
  sn=$(cat "$d/device/serial" 2>/dev/null)
  [ -n "$sn" ] && sn="SN $sn"
  say disk "$b" "$(cat "$d/device/model" 2>/dev/null) $sz $sn"
done
say firmware 'BIOS vendor' "$(dmi bios_vendor)"
say firmware 'BIOS version' "$(dmi bios_version)"
say firmware 'BIOS date' "$(dmi bios_date)"
say firmware 'Board' "$(dmi board_vendor) $(dmi board_name)"
say firmware 'Board serial' "$(dmi board_serial)"
"""

# macOS. `system_profiler` answers most of it in one call; `sw_vers` and `sysctl`
# fill the rest.
_MAC = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
n=0
say() {
  [ -n "$3" ] || return 0
  n=$((n+1))
  if [ "$n" -gt "$LIMIT" ]; then echo '#truncated'; exit 0; fi
  printf '%s|%s|%s\n' "$1" "$2" "$(printf '%s' "$3" | tr -d '|' | tr '\n' ' ')"
}
hw=$(system_profiler SPHardwareDataType 2>/dev/null)
field() { printf '%s\n' "$hw" | awk -F': ' -v k="$1" 'index($0, k) { sub(/^[ \t]+/, "", $2); print $2; exit }'; }
say system 'Model' "$(field 'Model Name')"
say system 'Model identifier' "$(field 'Model Identifier')"
say system 'Serial number' "$(field 'Serial Number')"
say system 'Hardware UUID' "$(field 'Hardware UUID')"
say system 'Hostname' "$(hostname)"
say os 'Name' "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
say os 'Build' "$(sw_vers -buildVersion 2>/dev/null)"
say os 'Kernel' "$(uname -sr)"
say os 'Architecture' "$(uname -m)"
say cpu 'Model' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null)$(field 'Chip')"
say cpu 'Cores' "$(field 'Total Number of Cores')"
say memory 'Total' "$(field 'Memory')"
say firmware 'Boot ROM' "$(field 'System Firmware Version')"
say firmware 'OS Loader' "$(field 'OS Loader Version')"
system_profiler SPStorageDataType 2>/dev/null | awk '
  /^ {4}[^ ].*:$/ { name=$0; sub(/^ */, "", name); sub(/:$/, "", name); gsub(/\|/, " ", name) }
  /Capacity:/ { sub(/^[ \t]*Capacity:[ \t]*/, ""); if (name != "") { print "disk|" name "|" $0; name="" } }'
"""


# Falcon's `platform_name`, lowercased, to the script that can read that OS.
# Matched on a prefix because the field is not a closed set: "Windows", "Linux",
# "Mac" and "macOS" have all been seen in the wild.
_SCRIPTS = (("win", "win"), ("mac", "mac"), ("linux", "linux"), ("ubuntu", "linux"),
            ("rhel", "linux"), ("centos", "linux"), ("debian", "linux"),
            ("amazon", "linux"), ("suse", "linux"), ("oracle", "linux"))

# The scripts to run on each OS, in order, as (label, body).
#
# Windows is **three** scripts rather than one, and not for tidiness: a
# `runscript -Raw` command travels as one string in a REST body, and that string
# is not unbounded. The single script came to 4.8 KB, which is close enough to the
# limits quoted for RTR that a host would refuse it — and a refused script comes
# back as empty output, which is indistinguishable from a machine with nothing to
# report. Splitting also buys failure granularity: if reading the scheduled tasks
# trips over one bad task, the Run keys have already been returned.
_PASSES = {
    "win": (("system and os", "_WIN_SYSTEM"), ("hardware", "_WIN_HARDWARE")),
    "linux": (("all", "_LINUX"),),
    "mac": (("all", "_MAC"),),
}


def _minify(script):
    """Drop comment-only and blank lines.

    The comments in these scripts are worth a great deal in this file and nothing
    at all on the wire, where they are the difference between a command that fits
    and one that may not: the autorun script carries far more explanation than the
    others, and an RTR command string is not unbounded. Only lines whose first
    non-space character is `#` go — so `echo '#begin'`, which starts with `echo`,
    is untouched, and no string literal is ever cut into.
    """
    kept = [ln for ln in script.split("\n")
            if ln.strip() and not ln.lstrip().startswith("#")]
    return "\n".join(kept) + "\n"


def _script_for(platform, limit=MAX_ROWS_PER_HOST):
    """The enumeration scripts for a Falcon `platform_name`, as (label, script).

    Raises [`_UnknownOS`] rather than guessing. Guessing would mean falling
    through to the shell script, and on a Windows host that does not fail
    cleanly — it comes back empty, and that host then reads as a machine with
    **no software installed**. Which is the one wrong conclusion this module must
    never invite, so an OS we cannot name is a visible failure instead. Falcon
    also reports iOS, Android and Kubernetes nodes; none can be enumerated this
    way.
    """
    p = (platform or "").strip().lower()
    which = next((kind for prefix, kind in _SCRIPTS if p.startswith(prefix)), None)
    if which is None:
        raise _UnknownOS(platform or "(not reported)")
    bodies = globals()
    out = []
    for label, name in _PASSES[which]:
        body = bodies[name]
    # This file is checked out with CRLF, so the literals above carry \r on
    # every line. PowerShell copes; /bin/sh does not — `LIMIT=400\r` compares
    # against a value with a carriage return in it and every `done` becomes an
    # unknown command. So the script is normalised to LF whichever platform it is
    # for, rather than leaving it to how this file happens to be checked out.
        script = _minify(body.replace("__LIMIT__", str(int(limit)))).replace("\r\n", "\n")
        # The script is sent inside an RTR ```…``` block, so a backtick anywhere
        # in it — including in a comment written out of Markdown habit — closes
        # that block early and corrupts the command on the wire. It fails as a
        # script that does not run rather than as an error anybody sees, so it is
        # caught here instead.
        if "`" in script:
            bad = next(n for n, ln in enumerate(script.splitlines(), 1) if "`" in ln)
            raise AssertionError(f"backtick in {label} for {platform}, line {bad}")
        if len(script) > MAX_SCRIPT_BYTES:
            raise AssertionError(
                f"{label} for {platform} is {len(script)}B, over the "
                f"{MAX_SCRIPT_BYTES}B a single runscript may carry — split it")
        out.append((label, script))
    return out


def _parse(stdout, hostname, host_id):
    """One host's stdout into facts, plus what the metadata lines said.

    A fact is `section | item | value` — not a list of like things, as the other
    fleet modules return, because this answers "what is this machine" rather than
    "what does it have many of". The order is kept as the host reported it: the
    script emits each section in the order somebody reads them, and sorting would
    only scatter that.
    """
    rows, flags = [], {"truncated": False, "error": "", "no_dmi": False}
    for line in (stdout or "").splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        if line.startswith("#"):
            if line == "#begin":
                pass  # only proves the script ran; `_rtr_one` already checked
            elif line == "#truncated":
                flags["truncated"] = True
            elif line == "#no-dmi":
                flags["no_dmi"] = True
            elif line.startswith("#err="):
                # The endpoint stayed silent and told us instead.
                flags["error"] = line[5:].strip()
            continue
        # The value is last and may contain a separator of its own (a part number
        # or a path), so the split is bounded and the remainder kept whole.
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        section, item, value = (p.strip() for p in parts)
        if not item or not value:
            continue
        rows.append({
            "host": hostname,
            "host_id": host_id,
            "section": section or "other",
            "item": item,
            "value": value,
        })
    return rows, flags


_GIB = 1024 ** 3
# Win32_Processor.Architecture, as Settings names it.
_ARCH = {"0": "x86", "5": "ARM", "9": "x64", "12": "ARM64"}


def _device_specs(rows):
    """Windows' "Device specifications", from the host's `about` facts.

    The lines Settings > System > About shows, in its order and formatted the
    way it formats them — the clock speed truncated rather than rounded, so the
    number matches the one on the machine's own screen; installed memory with
    the usable amount beside it when they differ; storage as used of total
    across the fixed drives. Empty for a host that sent no `about` facts, which
    is every host that is not Windows.

    Pen and touch are known only as present or not: whether a digitizer is
    there is read from the device list, and how many touch points it takes is
    not something the device list says.
    """
    about = {}
    gpus = []
    for r in rows:
        if r["section"] != "about":
            continue
        if r["item"] == "gpu":
            gpus.append(r["value"])
        else:
            about.setdefault(r["item"], r["value"])
    if not about and not gpus:
        return []

    def num(text):
        try:
            return float(text)
        except (TypeError, ValueError):
            return 0.0

    def dec(x, places):
        return f"{x:.{places}f}".replace(".", t("spec.decimal"))

    out = []
    if about.get("name"):
        out.append([t("spec.name"), about["name"]])
    if about.get("cpu"):
        mhz = num(about.get("cpu_mhz"))
        cpu = about["cpu"].strip()
        if mhz:
            # Truncated to two places, as Settings shows it: 2895 MHz is 2.89.
            cpu += " (" + t("spec.ghz", n=dec(int(mhz / 10) / 100, 2)) + ")"
        out.append([t("spec.processor"), cpu])
    installed = num(about.get("ram_installed")) / _GIB
    usable = num(about.get("ram_usable")) / _GIB
    if installed or usable:
        if installed and usable and installed - usable >= 0.05:
            ram = t("spec.ram_usable", installed=dec(installed, 1), usable=dec(usable, 1))
        else:
            ram = t("spec.gb", n=dec(installed or usable, 1))
        out.append([t("spec.ram"), ram])
    if gpus:
        out.append([t("spec.gpu"), ", ".join(gpus)])
    size = num(about.get("disk_size"))
    if size:
        used = size - num(about.get("disk_free"))
        out.append([t("spec.storage"), t("spec.storage_used",
                                         used=round(used / _GIB), total=round(size / _GIB))])
    if about.get("device_id"):
        out.append([t("spec.device_id"), about["device_id"].strip("{} ").upper()])
    if about.get("product_id"):
        out.append([t("spec.product_id"), about["product_id"]])
    if about.get("os64"):
        bits = "64" if about["os64"].strip().lower() == "true" else "32"
        arch = _ARCH.get(about.get("cpu_arch", "").strip())
        out.append([t("spec.system_type"),
                    t("spec.system_type_cpu", bits=bits, arch=arch) if arch
                    else t("spec.system_type_os", bits=bits)])
    if "touch" in about or "pen" in about:
        touch, pen = num(about.get("touch")) > 0, num(about.get("pen")) > 0
        out.append([t("spec.pen"), t("spec.pen_touch" if touch and pen else
                                     "spec.touch_only" if touch else
                                     "spec.pen_only" if pen else "spec.no_pen")])
    return out


def _headline(rows):
    """The one-line answer, before the detail.

    Model, OS and serial is what identifies a machine, and having to read three
    sections for it would make the common case the slow one.
    """
    head = facts_of(rows)
    return "   ·   ".join(v for v in [
        head.get("model"), head.get("os"), head.get("cpu"), head.get("memory"),
        f"SN {head['serial']}" if head.get("serial") else None,
    ] if v)


def facts_of(rows):
    """The headline facts, by the names another module would ask for.

    A fleet-wide question is almost never "give me every line"; it is "what OS",
    "what serial", "how much memory". Those are picked out here so a caller does
    not have to know which section each lives in, or that Windows calls a serial
    number one thing and DMI another.
    """
    want = {
        ("system", "Serial number"): "serial",
        ("system", "Manufacturer"): "manufacturer",
        ("system", "Model"): "model",
        ("os", "Name"): "os",
        ("os", "Version"): "os_version",
        ("os", "Kernel"): "kernel",
        ("cpu", "Model"): "cpu",
        ("memory", "Total"): "memory",
        ("system", "Memory installed"): "memory",
    }
    out = {}
    for r in rows:
        key = want.get((r["section"], r["item"]))
        # First wins: Windows reports memory under `system`, Linux under
        # `memory`, and a host that somehow reports both keeps the first.
        if key and key not in out:
            out[key] = r["value"]
    return out



def _int(v):
    """A pid as a number for sorting, and 0 for anything that is not one."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# Scanning: one worker per host, so a finished host is usable immediately.
# --------------------------------------------------------------------------- #
def _log(line):
    """Queue a line for the dispatch thread to log. Safe from any thread."""
    _logq.put(line)


def _set(hid, **fields):
    """Update one host's job state under the lock."""
    with _lock:
        job = _jobs.get(hid)
        if job is not None:
            job.update(fields)


def _read(hid, hostname, platform, token, base, stop):
    """Read one host over RTR, and say how it ended.

    Returns the fields of a finished read: `state`, with `facts` and `notes`
    when it is `done`, or `error` when it is not. Shared by the fleet scan and
    the one-host read another module asks for, so both read a machine the same
    way. Runs on a worker thread; touches only `_logq` and the network.
    """
    try:
        stdout = _rtr_one(hid, platform, token, base, stop)
        rows, flags = _parse(stdout, hostname, hid)
        notes = []
        if flags["truncated"]:
            notes.append(t("note.truncated", n=MAX_ROWS_PER_HOST))
        if flags["no_dmi"]:
            notes.append(t("note.no_dmi"))
        if flags["error"]:
            # The script caught something on the endpoint and reported it here
            # instead of showing it there. Surfaced as a note, not a failure: the
            # rows it did manage to send are still good.
            notes.append(flags["error"])
        if not rows and not notes:
            notes.append(t("note.empty"))
        _log(f"cs-sysinfo: {hostname} — {len(rows)} fact(s)")
        return {"state": "done", "facts": rows, "notes": notes}
    except _Stopped:
        return {"state": "stopped"}
    except _UnknownOS as exc:
        _log(f"cs-sysinfo: {hostname} skipped — {exc}")
        return {"state": "skipped", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        _log(f"cs-sysinfo: {hostname} failed — {exc}")
        return {"state": "failed", "error": str(exc)}


def _worker(hid, token, base, stop):
    """Enumerate one host of a fleet scan. Runs on a pool thread; touches only
    `_jobs` (locked), `_logq`, and the network."""
    with _lock:
        job = _jobs.get(hid)
        if job is None:
            return
        hostname, platform = job["hostname"], job["platform"]
    if stop.is_set():
        _set(hid, state="stopped")
        return
    _set(hid, state="scanning")
    _set(hid, **_read(hid, hostname, platform, token, base, stop))


def _start(host, targets):
    """Queue `targets` and start the pool. Returns the status line.

    The token is fetched **here**, on the dispatch thread, and handed to the
    workers: asking for it from a worker would mean using the host bridge off the
    RPC thread.
    """
    if not targets:
        return t("status.none_selected")
    if _busy():
        return t("status.already_running")
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-sysinfo: auth failed: {exc}")
        return str(exc)

    stop = threading.Event()
    with _lock:
        _jobs.clear()
        for target in targets:
            _jobs[target["id"]] = {
                "hostname": target.get("hostname") or target["id"],
                "platform": target.get("platform", ""),
                "state": "queued",
                "facts": [],
                "error": "",
                "notes": [],
            }
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets)))
    _run.update(pool=pool, stop=stop, started=time.time())
    for target in targets:
        pool.submit(_worker, target["id"], token, base, stop)
    # Nothing is waited on: the pool is left running and the view polls it, so
    # the dispatch thread returns to drawing immediately.
    host.log(f"cs-sysinfo: scanning {len(targets)} host(s) on "
             f"{min(MAX_WORKERS, len(targets))} thread(s)")
    return t("status.starting", n=len(targets))


def _busy():
    """Whether any host is still queued or in flight."""
    with _lock:
        return any(j["state"] in ("queued", "scanning") for j in _jobs.values())


def _drain_log(host):
    """Move whatever the workers queued into the host log. Dispatch thread only."""
    while True:
        try:
            host.log(_logq.get_nowait())
        except queue.Empty:
            return


def _tally():
    with _lock:
        states = [j["state"] for j in _jobs.values()]
        facts = sum(len(j["facts"]) for j in _jobs.values())
    return {
        "total": len(states),
        "done": states.count("done"),
        "failed": states.count("failed"),
        "stopped": states.count("stopped"),
        "skipped": states.count("skipped"),
        "running": states.count("scanning") + states.count("queued"),
        "facts": facts,
    }


def _targets_from(rows):
    return [
        {"id": h["id"], "hostname": h.get("hostname", ""),
         "platform": h.get("platform", "")}
        for h in rows
        if h.get("id")
    ]


# --------------------------------------------------------------------------- #
# Methods.
# --------------------------------------------------------------------------- #
@m.method("fetch")
def fetch(params, host):
    """Load the reachable inventory from the crowdstrike capability."""
    try:
        inv = host.call("crowdstrike", "hosts", {})
        # Only reachable hosts: RTR cannot open a session to a host that is
        # offline, so listing them as scannable would only produce failures.
        rows = inv.get("accessible", []) if isinstance(inv, dict) else []
        _hosts["rows"] = rows
        _status["msg"] = t("status.reachable", n=len(rows))
    except Exception as exc:  # noqa: BLE001
        _hosts["rows"] = None
        _status["msg"] = t("status.fetch_failed", err=exc)
        host.log(f"cs-sysinfo: fetch failed: {exc}")
    return m._view_spec()


@m.method("scan_selected")
def scan_selected(params, host):
    """Start scanning the ticked hosts."""
    rows = _hosts["rows"] or []
    selected = [h for h in rows if params.get(f"sel_{h.get('id')}")]
    _status["msg"] = _start(host, _targets_from(selected))
    return m._view_spec()


@m.method("scan_all")
def scan_all(params, host):
    """Start scanning every host in the current list."""
    _status["msg"] = _start(host, _targets_from(_hosts["rows"] or []))
    return m._view_spec()


@m.method("progress")
def progress(params, host):
    """One tick of the progress loop: drain the workers' log lines, wait a beat,
    and re-render.

    The wait is the throttle. The host re-invokes an `auto` action the moment the
    view renders, so answering immediately would spin the loop as fast as the two
    processes can pass frames.
    """
    _drain_log(host)
    if _busy():
        time.sleep(POLL_SECONDS)
    t = _tally()
    if t["running"]:
        _status["msg"] = (
            f"scanning — {t['done']} of {t['total']} done, "
            f"{t['facts']} fact(s) so far"
        )
    else:
        _shutdown_pool()
        parts = [f"{t['done']} host(s) scanned", f"{t['facts']} fact(s)"]
        if t["failed"]:
            parts.append(f"{t['failed']} failed")
        if t["stopped"]:
            parts.append(f"{t['stopped']} stopped")
        if t["skipped"]:
            parts.append(f"{t['skipped']} unsupported")
        _status["msg"] = " · ".join(parts)
    return m._view_spec()


def _shutdown_pool():
    """Let the finished pool go. Not blocking: every worker has already left."""
    pool = _run.get("pool")
    if pool is not None:
        pool.shutdown(wait=False)
        _run["pool"] = None


@m.method("stop")
def stop(params, host):
    """Call off the scan.

    A host already in flight finishes its current HTTP call — there is no way to
    un-ask a request that is out — but nothing new is started, and anything still
    queued is marked stopped rather than left looking as though it is coming.
    """
    ev = _run.get("stop")
    if ev is not None:
        ev.set()
    with _lock:
        for job in _jobs.values():
            if job["state"] == "queued":
                job["state"] = "stopped"
    host.log("cs-sysinfo: stop requested")
    _status["msg"] = t("status.stopping")
    return m._view_spec()


# --------------------------------------------------------------------------- #
# One host's facts, in its own tab.
# --------------------------------------------------------------------------- #
def columns():
    """Column headings, in the current language."""
    return [t("col.item"), t("col.value")]

# The order sections are shown in — what somebody identifying a machine reads
# first, not alphabetical. Anything the scripts add that is not listed here still
# appears, after these.
SECTION_ORDER = ["system", "os", "cpu", "memory", "disk", "display", "firmware"]

def section_title(section):
    """A section heading, translated. A section the scripts add that has no
    heading of its own falls back to its own name, title-cased."""
    key = "section." + section
    shown = t(key)
    return section.title() if shown == key else shown

# The filter text per open host tab, so two tabs can be narrowed differently.
_query = {}


def _sections(rows):
    """Group facts by section, in reading order."""
    out = {}
    for r in rows:
        # The raw values behind Device specifications: shown formatted, by
        # `_device_specs`, and never as a table of their own.
        if r["section"] == "about":
            continue
        out.setdefault(r["section"], []).append(r)
    order = [s for s in SECTION_ORDER if s in out]
    order += sorted(s for s in out if s not in SECTION_ORDER)
    return [(s, out[s]) for s in order]


@m.method("open_host")
def open_host(params, host):
    """A finished host's facts, opened in a tab. The double-click target."""
    _sync_locale()
    hid = str(params.get("id", ""))
    with _lock:
        job = dict(_jobs.get(hid) or {})
    if not job:
        return Window(t("ui.col_host"), [Label(t("host.unknown"))]).to_spec()
    name = job["hostname"]
    if job["state"] != "done":
        return Window(name, [
            Label(name, style="heading"),
            Label(state_text(job["state"]), style="weak"),
            Label(job["error"], style="weak") if job["error"] else Separator(),
        ]).to_spec()

    # A filter typed in this tab arrives with the call; otherwise the one this tab
    # was last left with, so a refresh does not silently widen the list.
    if "query" in params:
        _query[hid] = params.get("query") or ""
    query = (_query.get(hid) or "").lower()

    rows = job["facts"]
    widgets = [
        Label(name, style="heading"),
        Label(_headline(rows) or "—", style="weak"),
    ]
    for note in job["notes"]:
        widgets.append(Label("! " + note, style="weak"))
    widgets.append(Row([
        Text("query", label=t("ui.search"), placeholder=t("ui.search_hint"),
             default=_query.get(hid, "")),
        # Re-opens this same tab with the filter applied; the host id rides along
        # so the button knows which host it is filtering.
        Button(t("ui.filter"), calls="open_host", args={"id": hid}),
    ]))

    shown = 0
    specs = [s for s in _device_specs(rows)
             if not query or query in (s[0] + " " + s[1]).lower()]
    if specs:
        shown += len(specs)
        widgets += [Separator(), Label(t("spec.title"), style="strong"),
                    Table(columns(), specs)]
    for section, facts in _sections(rows):
        cells = [[f["item"], f["value"]] for f in facts
                 if not query or query in (f["item"] + " " + f["value"]).lower()]
        if not cells:
            continue
        shown += len(cells)
        widgets += [
            Separator(),
            Label(section_title(section), style="strong"),
            # No row actions: a fact is already the whole answer, so there is
            # nothing for a double-click to open.
            Table(columns(), cells),
        ]
    if shown == 0:
        widgets += [Separator(), Label(
            t("ui.no_match") if query else t("host.nothing"), style="weak")]
    elif query:
        widgets.append(Label(t("ui.shown_of", shown=shown, total=len(rows)),
                             style="weak"))
    return Window(name, widgets).to_spec()


@m.method("read_host")
def read_host(params, host):
    """One host's system info, read on request — for the host panel.

    ``{"id", "hostname", "platform"}``, as the ``crowdstrike`` inventory gives
    them. ``"refresh": true`` reads the host again; ``"start": false`` only says
    what is already known, for a host that is offline and cannot be asked.

    Returns at once. A read takes seconds, so this starts it and answers
    ``{"state": "scanning"}``; the caller asks again until it is ``done``,
    ``failed`` or ``skipped``. A finished read is kept, and answered from until
    a refresh — a failure too, so that a caller that polls does not start a new
    read on every frame of a screen that shows the error.

    A ``done`` answer is ready to show: ``headline``, ``columns`` and ``groups``
    (a title and its rows each) in the language Limen is in, and ``at`` — when it
    was read — plus every fact as ``section``/``item``/``value``. A Windows host
    also has ``specs``: a title and the lines of Settings' Device specifications.
    """
    _sync_locale()
    hid = str(params.get("id") or "")
    if not hid:
        return {"state": "failed", "error": "no host id"}
    with _lock:
        known = dict(_reads.get(hid) or {})
    if known and (known["state"] == "scanning" or not params.get("refresh")):
        return _read_answer(known)
    if not params.get("start", True):
        return _read_answer(known) if known else {"state": "none"}

    # The token is fetched here, on the dispatch thread, as for a fleet scan.
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-sysinfo: auth failed: {exc}")
        return {"state": "failed", "error": str(exc)}
    hostname = params.get("hostname") or hid
    platform = params.get("platform") or ""
    with _lock:
        _reads[hid] = {"state": "scanning", "at": 0.0, "started": time.time()}

    def run():
        done = _read(hid, hostname, platform, token, base, threading.Event())
        done["at"] = time.time()
        with _lock:
            _reads[hid] = done

    threading.Thread(target=run, name=f"cs-sysinfo-read-{hid}", daemon=True).start()
    host.log(f"cs-sysinfo: reading {hostname} for another module")
    return {"state": "scanning"}


def _read_answer(read):
    """What `read_host` says about a read, ready to show."""
    out = {
        "state": read["state"],
        "at": read.get("at", 0.0),
        "error": read.get("error", ""),
        "notes": list(read.get("notes", [])),
    }
    if read["state"] == "scanning":
        # How long it has been going, so a screen waiting on it can say so —
        # an RTR read takes tens of seconds, and a still screen reads as stuck.
        out["elapsed"] = int(time.time() - read.get("started", time.time()))
    if read["state"] == "done":
        rows = read["facts"]
        out["headline"] = _headline(rows)
        specs = _device_specs(rows)
        if specs:
            out["specs"] = {"title": t("spec.title"), "rows": specs}
        out["columns"] = columns()
        out["groups"] = [
            {"title": section_title(section),
             "rows": [[f["item"], f["value"]] for f in facts]}
            for section, facts in _sections(rows)
        ]
        out["facts"] = [{"section": r["section"], "item": r["item"],
                         "value": r["value"]} for r in rows]
    return out


@m.method("sysinfo")
def sysinfo(params, host):
    """The capability method: the scanned hosts as data, for other modules.

    Returns one entry per host rather than a flat list of facts, because that is
    the shape of the question — *what is each machine* — and a caller would only
    have to regroup a flat list to answer it.

    Each entry carries the headline facts at the top level (``os``, ``serial``,
    ``cpu``, ``memory``, ``model``) so a caller need not know which section each
    lives in, or that Windows files memory under the system and Linux under
    memory. ``facts`` holds everything, in the order the host reported it.

    ``{"item": "bios"}`` narrows to facts whose item or value contains it, across
    every host — which is how a firmware version is checked fleet-wide.
    """
    with _lock:
        if not _jobs:
            return {"error": "nothing scanned yet", "total": 0, "hosts": []}
        jobs = [(dict(j)) for j in _jobs.values()]
        failed = {j["hostname"]: j["error"] for j in jobs
                  if j["state"] in ("failed", "skipped")}
        # Computed here rather than by calling `_busy()`: that takes `_lock` too,
        # and `_lock` is a plain Lock, not an RLock.
        pending = any(j["state"] in ("queued", "scanning") for j in jobs)
    needle = (params.get("item") or "").strip().lower()
    hosts = []
    for j in jobs:
        if j["state"] != "done":
            continue
        rows = j["facts"]
        if needle:
            rows = [r for r in rows
                    if needle in r["item"].lower() or needle in r["value"].lower()]
            if not rows:
                continue
        entry = {"host": j["hostname"], "facts": [
            {"section": r["section"], "item": r["item"], "value": r["value"]}
            for r in rows]}
        entry.update(facts_of(j["facts"]))
        hosts.append(entry)
    return {
        "note": "What each CrowdStrike fleet host is, read over RTR. The headline "
                "facts are lifted to the top of each host; `facts` holds "
                "everything as `section`/`item`/`value`, in the order the host "
                "reported it.",
        "scanning": pending,
        "total": len(hosts),
        "failed_hosts": failed,
        "hosts": hosts,
    }

# --------------------------------------------------------------------------- #
# The screen.
# --------------------------------------------------------------------------- #
# What each job state says, and which `Step` icon it gets. "pending" is the idle
# dot, "loading" the spinner, "done" the check — so a failed or stopped host
# reads as finished-and-not-ok rather than as still going, which is the one thing
# it must never look like.
def state_text(state):
    """What a host's row says it is doing, in the current language."""
    return t("state." + state) if state in (
        "queued", "scanning", "done", "failed", "stopped", "skipped") else state
_STATE_ICON = {
    "queued": "pending",
    "scanning": "loading",
    "done": "done",
    "failed": "pending",
    "stopped": "pending",
    "skipped": "pending",
}


class Step:
    """A progress step: an animated spinner that morphs into a check.

    Built as a raw spec rather than imported, because the Python SDK has no `Step`
    even though the host renders one. Same for the view's `auto` below.
    """

    def __init__(self, label="", state="pending"):
        self.label, self.state = label, state

    def to_spec(self):
        return {"kind": "step", "label": self.label, "state": self.state}


def _host_lines(widgets, rows):
    """One line per host: the tick box that selects it, and — once a scan has
    touched it — the live state beside it."""
    with _lock:
        jobs = {hid: dict(j) for hid, j in _jobs.items()}
    for h in rows:
        hid = h.get("id", "")
        job = jobs.get(hid)
        line = [Checkbox(f"sel_{hid}", label=h.get("hostname", "?"))]
        if job:
            text = state_text(job["state"])
            if job["state"] == "done":
                head = facts_of(job["facts"])
                text = head.get("os") or f"{len(job['facts'])} fact(s)"
            elif job["state"] == "failed" and job["error"]:
                text = t("state.failed_why", why=job["error"][:60])
            line.append(Step(label=text, state=_STATE_ICON.get(job["state"], "pending")))
        widgets.append(Row(line))
        detail = "   ·   ".join(p for p in [
            h.get("os", ""),
            f"SN {h['serial']}" if h.get("serial") else "",
            h.get("tags", ""),
        ] if p)
        if detail:
            widgets.append(Label("      " + detail, style="weak"))


def _finished_table(widgets):
    """The hosts that have finished, double-click to open one.

    Separate from the lines above because a table row is what carries a
    double-click, and because it is the natural place to be told which hosts are
    ready to look at while the rest are still running.
    """
    with _lock:
        done = [(hid, dict(j)) for hid, j in _jobs.items() if j["state"] == "done"]
    if not done:
        return
    done.sort(key=lambda kv: kv[1]["hostname"].lower())
    rows, ids = [], []
    for hid, j in done:
        # The summary line is the answer for most people, so the overview table
        # carries it rather than a count of facts nobody asked for.
        head = facts_of(j["facts"])
        rows.append([j["hostname"], head.get("os", ""), head.get("model", ""),
                     head.get("serial", ""), head.get("memory", "")])
        ids.append(hid)
    widgets += [
        Separator(),
        Label(t("ui.scanned", n=len(rows)), style="strong"),
        Table([t("ui.col_host"), t("ui2.col_os"), t("ui2.col_model"),
               t("ui2.col_serial"), t("ui2.col_memory")], rows,
              row_ids=ids, on_activate=(CAP, "open_host"),
              menu=[MenuItem(t("ui.open_host"), capability=CAP, method="open_host",
                             open_in_tab=True)]),
    ]


def _failed_table(widgets):
    """Hosts that were not read, listed rather than counted.

    An absent host is the one case where an empty result means nothing at all, so
    the operator has to know which machine to go and look at by hand. Hosts whose
    OS this module cannot read are in here too: they are not failures, but they
    are equally not answers, and leaving them out would quietly shrink the fleet.
    """
    with _lock:
        bad = [dict(j) for j in _jobs.values() if j["state"] in ("failed", "skipped")]
    if not bad:
        return
    widgets += [
        Separator(),
        Label(t("ui.not_scanned", n=len(bad)), style="strong"),
        Table([t("ui.col_host"), t("ui.col_why")], sorted([[j["hostname"], j["error"]] for j in bad])),
    ]


@m.ui
def ui():
    _sync_locale()
    widgets = [
        Label(t("ui.title"), style="heading"),
        Label(t("ui.subtitle"), style="weak"),
    ]

    rows = _hosts["rows"]
    running = _busy()
    toolbar = [Button(t("ui.fetch_hosts"), calls="fetch", primary=rows is None,
                      enabled=not running)]
    if rows:
        toolbar.append(Button(t("ui.scan_selected"), calls="scan_selected",
                              primary=True, enabled=not running))
        toolbar.append(Button(t("ui.scan_all"), calls="scan_all",
                              enabled=not running))
        # Only offered while there is something to stop, so it is never a button
        # that does nothing.
        if running:
            toolbar.append(Button(t("ui.stop"), calls="stop", danger=True))
    widgets.append(Row(toolbar))

    if _status["msg"]:
        widgets.append(Label(_status["msg"], style="weak"))

    if rows is not None:
        widgets.append(Separator())
        widgets.append(Label(t("ui.reachable", n=len(rows)), style="strong"))
        if not rows:
            widgets.append(Label(t("ui.no_reachable"), style="weak"))
        _host_lines(widgets, rows)

    _finished_table(widgets)
    _failed_table(widgets)

    spec = Window(t("ui.title"), widgets).to_spec()
    # While anything is still running, ask the host to call `progress` as soon as
    # this has drawn — that loop is what makes the spinners move and the finished
    # hosts appear one at a time. It stops being emitted the moment the work is
    # done, which is what ends the loop.
    if running:
        spec["auto"] = {"capability": CAP, "method": "progress", "args": {}}
    return spec


if __name__ == "__main__":
    m.run()
