#  Basic Network Sniffer

A professional, beginner-friendly Python network packet sniffer created for the CodeAlpha cybersecurity internship task. It uses Scapy to capture authorized traffic on Kali Linux, displays a concise packet summary, maintains capture statistics, and writes structured records to CSV.

> **Authorized educational use only:** Capture traffic only on networks and devices you own or have explicit permission to monitor. This project does not decrypt HTTPS/TLS traffic, inject packets, modify traffic, harvest credentials, perform MITM attacks, or spoof ARP.

## Features

- Captures packets with Scapy and supports the default Scapy interface.
- Accepts an interface, packet count, BPF filter, and CSV output path from the command line.
- Identifies TCP, UDP, ICMP, other IPv4 traffic, and non-IPv4 traffic safely.
- Displays packet number, timestamp, IP addresses, ports, length, TTL, TCP flags, payload length, and a safe payload preview.
- Limits payload previews to 80 printable characters and replaces non-printable bytes with `.`.
- Tracks total, TCP, UDP, ICMP, other, and payload-bearing packets.
- Flushes every CSV row during capture so data is available immediately.
- Handles `Ctrl+C`, missing interfaces, output errors, and permission problems clearly.
- Creates the output directory automatically.

## Technologies Used

- Python 3
- Scapy
- Python standard library: `argparse`, `csv`, `dataclasses`, `datetime`, `pathlib`
- Kali Linux for packet capture and analysis

## Project Structure

```text
CodeAlpha-Network-Sniffer/
├── network_sniffer.py
├── requirements.txt
├── README.md
├── .gitignore
└── logs/
    └── .gitkeep
```

`logs/*.csv` is ignored by Git because captured traffic may contain sensitive information.

## Windows Development Instructions

Development and documentation can be completed in Windows VS Code. The actual packet capture is intentionally intended for Kali Linux because raw packet capture permissions and network tooling differ across operating systems.

1. Open the `CodeAlpha-Network-Sniffer` folder in VS Code.
2. Review or edit `network_sniffer.py` and `README.md` on Windows.
3. Run the syntax check below. It does not capture traffic:

```powershell
python -m py_compile network_sniffer.py
```

4. Copy the project to Kali Linux using Git, a private repository, or another secure transfer method.

Scapy may install on Windows, but this project does not require Windows packet capture and does not promise that capture permissions or interfaces will behave there.

## Kali Linux Installation

From the project directory on Kali Linux:

```bash
sudo apt update
sudo apt install python3 python3-pip
pip3 install scapy
```

If Kali prevents system-wide `pip3` installation, use a virtual environment:

```bash
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Find the Network Interface

List available interfaces with either command:

```bash
ip link show
```

```bash
sudo python3 -c "from scapy.all import get_if_list; print('\\n'.join(get_if_list()))"
```

Common names include `eth0`, `wlan0`, and names beginning with `en` or `wl`. Use the interface connected to the authorized lab network.

## Run the Sniffer

Packet capture may require elevated privileges on Kali Linux:

```bash
sudo python3 network_sniffer.py
```

When using the virtual environment, activate it first and run:

```bash
sudo .venv/bin/python network_sniffer.py
```

Stop a live capture with `Ctrl+C`. The summary is written to `logs/packets.csv` by default.

## Example Commands

Capture on the default Scapy interface:

```bash
sudo python3 network_sniffer.py
```

Capture 20 packets on `eth0`:

```bash
sudo python3 network_sniffer.py -i eth0 -c 20
```

Capture TCP traffic on `wlan0`:

```bash
sudo python3 network_sniffer.py -i wlan0 -f tcp
```

Capture 50 packets to a custom CSV path:

```bash
sudo python3 network_sniffer.py -i wlan0 -c 50 -o logs/capture.csv
```

Scapy BPF filters such as `tcp`, `udp`, and `icmp` can be passed with `-f`.

View all command-line options:

```bash
python3 network_sniffer.py --help
```

## CSV Output

The CSV file contains one summarized row per captured packet:

| Column | Meaning |
| --- | --- |
| `packet_number` | Sequential number assigned during this run |
| `timestamp` | Local timestamp formatted as `YYYY-MM-DD HH:MM:SS` |
| `source_ip`, `destination_ip` | IPv4 addresses, or `N/A` for non-IPv4 packets |
| `protocol` | `TCP`, `UDP`, `ICMP`, `OTHER IPv4`, or `OTHER` |
| `source_port`, `destination_port` | Transport ports where available |
| `packet_length` | Full Scapy packet length in bytes |
| `ttl` | IPv4 time-to-live, or `N/A` |
| `tcp_flags` | TCP flags, or `N/A` |
| `payload_length` | Length of the detected raw payload |
| `payload_preview` | At most 80 printable characters; sensitive payloads should still be treated carefully |

The output file is flushed after every row. It is overwritten when a new capture starts at the same path.

## Example Output

```text
===============================================================
             CODEALPHA BASIC NETWORK SNIFFER
===============================================================

[INFO] Authorized-use educational tool
[INFO] Capture only traffic you are permitted to monitor.

=======================================================================================
Packet #1
Timestamp       : 2026-09-17 14:30:21
Source IP       : 192.168.1.10
Destination IP  : 142.250.72.14
Protocol        : TCP
Source Port     : 54321
Destination Port: 443
Packet Length   : 74 bytes
TTL             : 64
TCP Flags       : S
Payload Length  : 0 bytes
Payload Preview : No payload
```

At capture end, the tool prints total, TCP, UDP, ICMP, other, and payload-bearing packet counts.

## Troubleshooting

**Permission denied:** Run the capture with `sudo`, or use a configured virtual environment with the required Linux capture permissions.

**Interface not found:** Check `ip link show`, then pass the exact interface name with `-i`.

**No packets appear:** Confirm the interface is active, create authorized lab traffic, and check that a BPF filter is not too restrictive.

**Scapy cannot be imported:** Activate the virtual environment and run `python -m pip install -r requirements.txt`.

**Output path errors:** Ensure the directory is writable. The project creates missing parent directories automatically.

**Capture stops unexpectedly:** Check the terminal error, confirm the interface remains available, and verify that the command has sufficient permissions.

## Ethical and Legal Usage

Network packets can contain private communications, identifiers, and other sensitive data. Use this tool only for systems and networks where you have explicit authorization. Do not publish captured CSV files, use the tool to bypass security controls, decrypt protected traffic, intercept other users' communications, or modify network traffic. The safe learning environment is an isolated lab, a personal machine, or an approved internship exercise.

## CodeAlpha Internship Task Reference

This project is a polished submission for the **CodeAlpha Basic Network Sniffer** cybersecurity internship task. Development was completed in Windows VS Code, while packet capture is designed to be executed on Kali Linux with Scapy and the appropriate permissions.
