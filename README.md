# OS Fingerprinter

A C-based tool that identifies the Operating System of a remote computer.
It uses **Raw Sockets** to send custom TCP packets and analyzes the responses to determine if the target is **Linux/Unix** or **Windows**.

## Key Features

* **Hybrid Detection Engine:** Combines two methods for best results:
    1.  **Database Matching:** Compares the response against the official **Nmap Database** (6,000+ signatures).
    2.  **Behavioral Analysis:** If no exact match is found, it guesses the OS based on how it handles "illegal" packets (Heuristics).
* **7-Stage Probe (T1-T7):** Runs a full suite of tests (SYN, Null, Xmas, ACK, etc.) similar to Nmap.
* **Raw Sockets:** Manually constructs TCP/IP headers from scratch.
* **Automatic IP Detection:** Automatically detects the local network interface.

## 📂 Project Structure

```text
os_fingerprinter/
├── bin/                  # The compiled program (executable)
├── data/                 # External Nmap database file
├── include/              # Header files (.h)
├── src/                  # Source code (.c)
│   ├── main.c            # Main logic & Test orchestration
│   ├── network.c         # Raw socket sending/receiving
│   ├── matcher.c         # Database matching logic
│   ├── db_parser.c       # Loading Nmap DB
│   └── utils.c           # Helper functions (Checksums, IP)
└── Makefile              # Build instruction file

How to Run
1) Compile the project:
make

2) Run the tool: You must use sudo because creating Raw Sockets requires root privileges.
sudo ./bin/fingerprinter <TARGET_IP>

3) Example:
sudo ./bin/fingerprinter 127.0.0.1

How It Works (The Logic)
The tool performs a Binary Classification (Linux vs. Windows) using the following logic:
Phase 1: Database Search (T1) It sends a standard SYN packet. It checks the response (TTL and Window Size) against the Nmap database. If an exact match is found, it prints the specific OS version.
Phase 2: Behavioral Analysis (T2 - T7) It sends "malformed" packets (like the Xmas Scan or Null Scan).
Linux / Unix: Follows the strict RFC rules. It replies with a RST packet (saying "Port closed / Error").
Windows: Ignores these packets for security reasons (Firewall drops them).
By counting these responses, the tool decides the OS family even if the database search fails.