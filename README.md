# NetScalerIOC

A small incident-response toolkit for **Citrix NetScaler ADC / NetScaler Gateway** appliances.

The repository currently contains two shell scripts:

- **`iocADM.sh`** — a reusable IOC scanner with 30 checks for suspicious files, processes, log entries, persistence mechanisms and runtime behavior.
- **`Collect-NetScalerEvidence.sh`** — an interactive evidence collector that preserves volatile state, logs, configuration and existing crash artifacts, and can optionally generate an NSPPE core dump.

The scripts are intended for administrators who already understand NetScaler HA, shell access and the operational impact of restarting a Packet Engine. They are not a substitute for vendor support or a full forensic investigation.

## IOC scanner

`iocADM.sh` is designed to run manually or as a scheduled task from NetScaler Console.

It has no command-line parameters.

### Cutoff logic

The scanner normally starts at:

```text
last firmware installation timestamp + 30 minutes
```

An optional incident-specific cutoff can be set near the top of the script:

```bash
SPECIAL_CUTOFF_DATE="2026-09-01 00:00:00"
```

The **latest** of the firmware cutoff and `SPECIAL_CUTOFF_DATE` wins. This avoids repeatedly scanning periods that were already covered by an earlier vendor-fixed firmware release, while still allowing a newly published incident window to be enforced.

Set it to an empty string to disable the special cutoff:

```bash
SPECIAL_CUTOFF_DATE=""
```

### IOC output

Findings are written to:

```text
/nsconfig/scripts/iocADM.log
```

IOC findings are also sent through `logger` with an `[IOC]` tag, making them suitable for forwarding through the appliance logging pipeline.

### Current checks

The scanner currently checks for, among other things:

- unexpected PHP files in NetScaler web paths
- modified files in logon and Python locations
- suspicious Apache graceful-restart entries
- NSPPE core files
- shell and Perl references in HTTP error logs
- suspicious shell/bash log keywords
- unexpected processes running as `nobody`
- filtered crontab entries
- unexpected Python and Perl processes
- suspicious command patterns in logs
- new SUID-root files
- `callhome_tmps` artifacts
- unexpected SUID binaries
- reverse-shell/backdoor patterns in `rc.netscaler`
- unexpected `ProxyPass` rules
- `getAuthenticationRequirements` changes
- suspicious headers, user agents and POST requests
- suspicious children spawned directly by `httpd`
- scripts/executables in writable temporary directories
- suspicious listening shell/interpreter/netcat-like processes
- additional persistence patterns in `rc.netscaler`

A clean scan means **no indicators were found by these checks**. It does not prove that compromise never occurred.

## Evidence collector

`Collect-NetScalerEvidence.sh` is interactive when run normally.

It first collects non-disruptive evidence and then asks:

```text
Generate an NSPPE core dump as well? This will trigger a warm restart. [y/N]:
```

If the answer is **No**, the script creates one final archive immediately.

If the answer is **Yes**, it:

1. captures volatile state before any restart
2. copies the locally available logs, configuration and existing crash/core data
3. creates a pre-reboot archive
4. installs a temporary one-shot boot hook in `/nsconfig/rc.netscaler`
5. configures the Citrix Packet Engine abort policy
6. triggers an NSPPE core dump, which causes a warm restart
7. automatically resumes after boot
8. removes its own one-shot hook
9. restores the default Packet Engine policy
10. collects the post-reboot NSPPE core(s)
11. produces one final `.tar.gz` archive

The original `rc.netscaler` is copied into the evidence set **before** the temporary run-once hook is added.

### Collected data

The bundle includes, where available:

- process listings and parent/child relationships
- `top`, mount and filesystem information
- interface, connection and routing state
- `sockstat`
- selected CPU/RAM/Packet Engine sysctls
- `newnslog` time span and events
- `adc.version`
- `ns.conf` and previous configuration files
- `rc.netscaler`
- `/etc/crontab`
- the IOC scanner and its log
- the complete locally available `/var/log`
- the complete locally available `/var/nslog`
- `/var/core`
- `/var/crash`
- an existing `support.tgz`, if already present
- metadata for IOC-relevant filesystem locations
- SHA-256 hashes of collected text/configuration/state files

Private SSL keys are intentionally not copied.

The final archive is written to:

```text
/var/tmp/<hostname>-Evidence-<timestamp>.tar.gz
```

## Operational warning

Generating an NSPPE core is **disruptive** and causes a warm restart. Use that option only when you understand the HA state and operational impact. On an HA pair, collecting from a passive node is usually the least disruptive place to preserve volatile evidence.

## Compatibility

The scripts target the FreeBSD-based shell environment used by Citrix NetScaler ADC / NetScaler Gateway and intentionally use appliance-native tooling where possible.

## Background

This toolkit was built while responding to Citrix NetScaler security advisories and evolving IOC guidance. The goal is deliberately practical: preserve useful evidence, scan for multiple classes of compromise artifacts, and avoid relying on a single IOC list that may change as an investigation develops.

## Disclaimer

Use at your own risk. Test in your own environment before broad deployment. A negative result is not proof of absence of compromise, and a positive result should be validated before taking destructive remediation actions.
