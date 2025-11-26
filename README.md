# OS Fingerprinter (Raw Sockets Implementation)

A C-based OS Fingerprinting tool that identifies remote operating systems by analyzing their TCP/IP stack behavior.
This project runs on Linux (WSL/Ubuntu) and uses **Raw Sockets** to construct custom packets and analyze responses.

## Features

* **Custom Packet Injection:** Uses `SOCK_RAW` to manually build TCP/IP headers.
* **Automatic IP Detection:** Automatically detects the source interface IP to calculate correct checksums.
* **Multi-Stage Probing:**
    * **Test T1 (Connectivity):** Sends a standard TCP SYN packet.
    * **Test T7 (Xmas Scan):** Sends a malformed packet (FIN | PUSH | URG) to test OS-specific error handling.
* **Heuristic Matching:** Analyzes TTL (Time To Live) and Window Size to guess the OS family.

## 📂 Project Structure

```text
os_fingerprinter/
├── bin/                  # Compiled executable
├── data/                 # External Nmap database
├── include/              # Header files (.h)
├── src/                  # Source code (.c)
│   ├── main.c            # Entry point & Test orchestration
│   ├── network.c         # Raw socket sending/receiving logic
│   ├── utils.c           # Checksum calc & IP detection
│   └── matcher.c         # OS Analysis logic
└── Makefile              # Build automation