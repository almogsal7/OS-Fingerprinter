# OS Fingerprinter

A simple tool to identify the operating system running on a remote host.

## What it does

This tool sends special TCP packets to a target and analyzes the responses.
Different operating systems have different "fingerprints" - unique patterns in
how they respond to network traffic.

We focus on detecting:
- **Windows** (7, 10, 11, Server editions)
- **Linux** (Ubuntu etc.)
- **Android TV** and similar devices

## How to build

```bash
make
```

## How to use

You need to run as root (for raw socket access):

```bash
# Auto-detect port
sudo ./bin/os_fingerprint 192.168.1.100

# Specify a port
sudo ./bin/os_fingerprint 192.168.1.100 22
```

## Requirements

- Linux system
- Root privileges
- nmap's fingerprint database (`nmap-os-db`)

Copy the database file to the `data/` folder:
```bash
mkdir -p data
cp /usr/share/nmap/nmap-os-db data/
```

## How it works

1. **Port scanning**: Find an open TCP port on the target
2. **T1 (SYN probe)**: Send a normal connection request, analyze the response
3. **T2 (NULL probe)**: Send a packet with no flags, see if target responds
4. **T3 (XMAS probe)**: Send a packet with unusual flags
5. **Matching**: Compare responses against thousands of known fingerprints

## Probes explained

| Probe | What it does | What we learn |
|-------|--------------|---------------|
| T1 | SYN to open port | TTL, Window size, TCP options |
| T2 | NULL packet (no flags) | Behavioral test |
| T3 | XMAS packet (weird flags) | Behavioral test |

## Example output

```
================================================
  OS Fingerprinter v1.0
  Target: 192.168.1.100
================================================

Looking for an open port...
   Port 22: open

Using port 22 for fingerprinting.

Loading fingerprint database... done (6000+ entries)

Running fingerprint probes...
   Sending T1 (SYN) probe... response (TTL=64, Win=65535)
   Sending T2 (NULL) probe... no response
   Sending T3 (XMAS) probe... no response

============================================
 Scan Results
============================================
TTL:     64 (Linux/Android)
Window:  65535
Options: M5B4NW8ST11
DF flag: Y

Behavioral responses:
  T2 (NULL): no
  T3 (XMAS): no

============================================
 Top 3 Matches
============================================

#1  Linux 5.4 - 5.15
    Score: 650
    Type:  Linux/Android

#2  Ubuntu 20.04 (Linux 5.4)
    Score: 620
    Type:  Linux/Android

#3  Android 10 - 12 (Linux 4.19 - 5.10)
    Score: 580
    Type:  Linux/Android

--------------------------------------------
Best guess: Linux 5.4 - 5.15
Confidence: HIGH
```

## Notes

- This tool requires an open port to work
- Apple devices usually don't have open ports, so they can't be fingerprinted
- The tool uses the same techniques as nmap's `-O` option
