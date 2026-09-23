# limen-crowdstrike-sysinfo

What each CrowdStrike fleet host actually **is**, read over Real Time Response —
OS and build, serial numbers, CPU, memory down to the DIMM, disks, firmware and
uptime.

The msinfo32 answer, for every host at once.

## Why ask the host

Falcon's inventory knows a host's OS and the agent's own serial. It does not know
which DIMM slots are filled, what the BIOS version is, whether Secure Boot is on,
or what the board's serial is — and those are the questions asked when a machine
is being replaced, audited, or explained.

One RTR session **per host**, on a small thread pool. Tick the hosts, press Scan,
and the list fills in as answers arrive — a spinner beside each host while it
runs, and a double-click on any finished host opens its details in a tab **while
the rest are still scanning**. Stop calls off whatever has not started.

## What it reads

| Platform | Sources |
|---|---|
| Windows | `Win32_ComputerSystem`, `…Product`, `…OperatingSystem`, `BIOS`, `BaseBoard` — then `Processor`, `PhysicalMemory`, `DiskDrive`, `VideoController` |
| Linux | DMI under `/sys/class/dmi/id`, `/etc/os-release`, `/proc`, and `dmidecode` for per-DIMM detail where installed |
| macOS | `system_profiler`, `sw_vers`, `sysctl` |

**Windows goes in two passes** — what the machine *is*, then what is *in* it. The
second is the slower one, so a host that refuses or times out on the hardware
walk still returns its OS and serial, which is most of what anyone asks for. A
failed pass reports which part is missing rather than leaving a short list that
looks complete.

**Memory is listed per DIMM**, not just as a total. A machine with one stick in a
four-slot board is a different machine from one that is full, and only the slot
list says which.

**DMI is root-only**, which RTR is — so the serials read. If they ever do not,
the host's row says `DMI was not readable, so the serial numbers are missing
rather than absent`, because a blank serial and a machine without one are not the
same thing.

## Nothing shows on the endpoint

Every PowerShell output stream is set to `SilentlyContinue`, each pass is wrapped
so an unforeseen throw cannot surface, and on Unix `stderr` is closed for the
whole script. No files are written and no window is opened.

Read-only: inventory tables are read and nothing is changed. But read-only is a
property of the script, not of the permission, so the permission stays the honest
one — `run_hosts`. **This executes code on your fleet.**

## It needs no privileges on your own machine

`network` and `run_hosts`, and nothing else. No `admin`, no `elevate`, no
`may_require_admin`. The privilege it needs is remote and Falcon-side — the RTR
admin tier for `runscript` — a scope on your API client.

## Requires

* The [`crowdstrike`](https://github.com/CRC-BARRACUDA/limen-crowdstrike) module,
  configured. It owns the credentials; this module owns none.
* RTR enabled, with the admin tier on the API client.

## Capability

Provides `crowdstrike.sysinfo`.

```
sysinfo                  -> one entry per host
sysinfo {"item": "bios"} -> only facts whose item or value contains it
```

Returns **one entry per host**, not a flat list of facts — that is the shape of
the question. Each entry lifts the headline facts to the top (`os`, `serial`,
`cpu`, `memory`, `model`) so a caller need not know which section each lives in,
or that Windows files memory under the system and Linux under memory. `facts`
holds everything as `section`/`item`/`value`, in the order the host reported it.

## Licence

GPL-3.0-or-later.
