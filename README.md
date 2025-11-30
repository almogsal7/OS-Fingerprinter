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
2. **SYN probe**: Send a normal connection request, analyze the response
3. **NULL probe**: Send a packet with no flags, see if target responds
4. **XMAS probe**: Send a packet with unusual flags
5. **ACK probe**: Send an acknowledgment to a non-existent connection
6. **Matching**: Compare responses against thousands of known fingerprints

## Example output

```
================================================
  Target: 192.168.1.100
================================================

Looking for an open port...
   Port 22: open

Using port 22 for fingerprinting.

Loading fingerprint database... done (6000+ entries)

Running fingerprint probes...
   Sending SYN probe... got response (TTL=64, Win=65535)
   Sending NULL probe... no response
   Sending XMAS probe... no response
   Sending ACK probe... response

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

- Apple devices usually don't have open ports, so they can't be fingerprinted this way
- Results are best when you have an open port that accepts connections
- The tool uses the same techniques as nmap's `-O` option
