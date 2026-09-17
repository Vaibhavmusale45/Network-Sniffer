#!/usr/bin/env python3
""" Basic Network Sniffer.

This tool is intended for authorized educational and laboratory use only.
Packet capture should be performed on Kali Linux or another Linux system.
"""

import argparse
import csv
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from scapy.all import ICMP, IP, TCP, UDP, Raw, conf, sniff


BANNER = """===============================================================
              BASIC NETWORK SNIFFER
===============================================================

[INFO] Authorized-use educational tool
[INFO] Capture only traffic you are permitted to monitor.
"""

CSV_FIELDS = [
    "packet_number",
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_length",
    "ttl",
    "tcp_flags",
    "payload_length",
    "payload_preview",
]


@dataclass
class CaptureStats:
    """Counters maintained while packets are captured."""

    total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    other: int = 0
    with_payload: int = 0

    def record(self, protocol: str, has_payload: bool) -> None:
        self.total += 1
        if protocol == "TCP":
            self.tcp += 1
        elif protocol == "UDP":
            self.udp += 1
        elif protocol == "ICMP":
            self.icmp += 1
        else:
            self.other += 1
        if has_payload:
            self.with_payload += 1


def positive_integer(value: str) -> int:
    """Validate argparse values that must be positive integers."""
    try:
        parsed_value = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed_value <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed_value


def safe_payload_preview(payload: bytes, maximum_length: int = 80) -> str:
    """Return printable ASCII only, limited to a safe terminal preview."""
    preview = payload[:maximum_length]
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in preview)


def packet_timestamp(packet: Any) -> str:
    """Format Scapy's packet timestamp for terminal and CSV output."""
    return datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")


def extract_packet_info(packet: Any, packet_number: int) -> Dict[str, Any]:
    """Extract display and CSV fields without assuming IPv4 is present."""
    packet_info: Dict[str, Any] = {
        "packet_number": packet_number,
        "timestamp": packet_timestamp(packet),
        "source_ip": "N/A",
        "destination_ip": "N/A",
        "protocol": "OTHER",
        "source_port": "N/A",
        "destination_port": "N/A",
        "packet_length": len(packet),
        "ttl": "N/A",
        "tcp_flags": "N/A",
        "payload_length": 0,
        "payload_preview": "No payload",
    }

    if IP in packet:
        ip_layer = packet[IP]
        packet_info["source_ip"] = ip_layer.src
        packet_info["destination_ip"] = ip_layer.dst
        packet_info["ttl"] = ip_layer.ttl

        if TCP in packet:
            transport_layer = packet[TCP]
            packet_info["protocol"] = "TCP"
            packet_info["source_port"] = transport_layer.sport
            packet_info["destination_port"] = transport_layer.dport
            packet_info["tcp_flags"] = str(transport_layer.flags)
        elif UDP in packet:
            transport_layer = packet[UDP]
            packet_info["protocol"] = "UDP"
            packet_info["source_port"] = transport_layer.sport
            packet_info["destination_port"] = transport_layer.dport
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
        else:
            packet_info["protocol"] = "OTHER"

    payload = bytes(packet[Raw].load) if Raw in packet else b""
    packet_info["payload_length"] = len(payload)
    if payload:
        packet_info["payload_preview"] = safe_payload_preview(payload)

    return packet_info


def display_packet(packet_info: Dict[str, Any]) -> None:
    """Print one readable packet summary without dumping full payload data."""
    print("=" * 87)
    print(f"Packet #{packet_info['packet_number']}")
    print(f"Timestamp       : {packet_info['timestamp']}")
    print(f"Source IP       : {packet_info['source_ip']}")
    print(f"Destination IP  : {packet_info['destination_ip']}")
    print(f"Protocol        : {packet_info['protocol']}")
    print(f"Source Port     : {packet_info['source_port']}")
    print(f"Destination Port: {packet_info['destination_port']}")
    print(f"Packet Length   : {packet_info['packet_length']} bytes")
    print(f"TTL             : {packet_info['ttl']}")
    print(f"TCP Flags       : {packet_info['tcp_flags']}")
    print(f"Payload Length  : {packet_info['payload_length']} bytes")
    print(f"Payload Preview : {packet_info['payload_preview']}")


def display_statistics(stats: CaptureStats) -> None:
    """Print the final capture counters."""
    print("\n============================================================")
    print("                 CAPTURE STATISTICS")
    print("============================================================")
    print(f"Total Packets  : {stats.total}")
    print(f"TCP Packets    : {stats.tcp}")
    print(f"UDP Packets    : {stats.udp}")
    print(f"ICMP Packets   : {stats.icmp}")
    print(f"Other Packets  : {stats.other}")
    print(f"With Payload   : {stats.with_payload}")
    print("============================================================")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Capture and summarize authorized IPv4 network traffic with Scapy."
    )
    parser.add_argument("-i", "--interface", help="Interface to sniff on (Scapy default if omitted).")
    parser.add_argument("-c", "--count", type=positive_integer, help="Number of packets to capture.")
    parser.add_argument("-f", "--filter", help="Scapy BPF filter, for example: tcp, udp, or icmp.")
    parser.add_argument(
        "-o",
        "--output",
        default="logs/packets.csv",
        help="CSV output path (default: logs/packets.csv).",
    )
    return parser


def prepare_output_file(output_path: str):
    """Create the output directory and return an initialized CSV writer and file."""
    csv_path = Path(output_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    csv_file = csv_path.open("w", newline="", encoding="utf-8")
    csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
    csv_writer.writeheader()
    csv_file.flush()
    return csv_file, csv_writer


def run_capture(arguments: argparse.Namespace) -> CaptureStats:
    """Capture packets and write each summarized record immediately."""
    stats = CaptureStats()
    csv_file, csv_writer = prepare_output_file(arguments.output)
    packet_number = 0

    def process_packet(packet: Any) -> None:
        nonlocal packet_number
        packet_number += 1
        packet_info = extract_packet_info(packet, packet_number)
        stats.record(packet_info["protocol"], packet_info["payload_length"] > 0)
        display_packet(packet_info)
        csv_writer.writerow(packet_info)
        csv_file.flush()

    try:
        print(f"[INFO] Writing packet summaries to: {arguments.output}")
        print(f"[INFO] Interface: {arguments.interface or conf.iface}")
        if arguments.filter:
            print(f"[INFO] BPF filter: {arguments.filter}")
        print("[INFO] Capture started. Press Ctrl+C to stop.\n")
        sniff(
            iface=arguments.interface,
            filter=arguments.filter,
            count=arguments.count or 0,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user (Ctrl+C).")
    finally:
        csv_file.close()

    return stats


def main() -> int:
    """Parse arguments, run capture, and handle common capture errors."""
    print(BANNER)
    parser = build_parser()
    arguments = parser.parse_args()

    try:
        stats = run_capture(arguments)
    except PermissionError:
        print(
            "[ERROR] Permission denied. On Kali Linux, retry with sudo or grant "
            "the required capture capabilities.",
            file=sys.stderr,
        )
        return 1
    except OSError as error:
        print(f"[ERROR] Capture could not start: {error}", file=sys.stderr)
        print("[INFO] Check the interface name and run with appropriate permissions.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"[ERROR] Invalid capture configuration: {error}", file=sys.stderr)
        return 1

    display_statistics(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
