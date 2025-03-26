import re
import subprocess
import time
import argparse
import socket


def get_machine_ip():
    """
    Get the primary IP address of the machine.
    Prefers non-loopback IPv4 addresses.
    """
    try:
        # Create a temporary socket to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually send any packets
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback to localhost if detection fails
        return "127.0.0.1"


# Updated regex patterns to match the detailed tcpdump output
connection_pattern = r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags\s+\[([^\]]+)\],\s+cksum\s+0x[0-9a-f]+"
arp_pattern = r"ARP,\s+Ethernet\s+\(len\s+\d+\),\s+IPv4\s+\(len\s+\d+\),\s+(Request|Reply)\s+who-has\s+(\d+\.\d+\.\d+\.\d+)\s+tell\s+(\d+\.\d+\.\d+\.\d+)"
length_pattern = r"length\s+(\d+)$"
ip_length_pattern = r"length\s+(\d+)\)$"
payload_pattern = r"^\s+0x[0-9a-f]+:\s+[0-9a-f\s]+"


# Function to interpret TCP flags
def interpret_flags(flags):
    flag_meanings = {
        "S": "SYN (Connection Request)",
        ".": "ACK (Acknowledgment)",
        "P": "PSH (Push Data)",
        "F": "FIN (Finish)",
        "R": "RST (Reset)",
        "U": "URG (Urgent)",
        "W": "Window Update",
        "E": "ECE (Explicit Congestion Notification)",
        "C": "CWR (Congestion Window Reduced)",
    }

    return " + ".join([flag_meanings.get(flag, flag) for flag in flags])


# Function to determine connection status
def determine_connection_status(flags):
    if "S" in flags and "." not in flags:
        return "Connection Attempt"
    elif "S" in flags and "." in flags:
        return "Connection Established"
    elif "R" in flags:
        return "Connection Rejected/Reset"
    elif "F" in flags:
        return "Connection Closing"
    elif "P" in flags:
        return "Data Transfer"
    else:
        return "Active Connection"


# Function to run tcpdump with payload capture
def run_tcpdump(show_payload=True):
    cmd = ["tcpdump", "-n", "-l", "-v"]
    if show_payload:
        cmd.append("-X")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process


# Monitor connections
def monitor_connections(
    show_localhost=False,
    filter_status=None,
    filter_protocol=None,
    filter_flags=None,
    filter_port=None,
    show_payload=True,
):
    # Get machine IP
    machine_ip = get_machine_ip()
    print(f"Monitoring connections. Machine IP: {machine_ip}")

    tcpdump_process = run_tcpdump(show_payload)
    payload_buffer = []
    current_connection = None
    protocol_length = "0"  # Protocol payload length
    total_length = "0"   # Total IP packet length
    skip_payload = False  # New flag to track if we should skip payload

    try:
        while True:
            line = tcpdump_process.stdout.readline()

            if not line:
                if tcpdump_process.poll() is not None:
                    print("tcpdump process terminated unexpectedly.")
                    break
                time.sleep(0.1)
                continue

            # Try to extract packet length from connection line (Protocol payload length)
            length_match = re.search(length_pattern, line)

            # If not found, try IP line length (Total IP packet length)
            if not length_match:
                length_match = re.search(ip_length_pattern, line)
                if length_match:
                    total_length = length_match.group(1)
            else:
                protocol_length = length_match.group(1)

            # Match connection details
            conn_match = re.search(connection_pattern, line)
            if not conn_match:
                # Try to match ARP packets
                arp_match = re.search(arp_pattern, line)
                if arp_match:
                    # If we have a previous payload, print it before starting new connection
                    if payload_buffer and not skip_payload:
                        print("Payload:")
                        print("\n".join(payload_buffer))
                        print("-" * 40)
                        payload_buffer = []

                    # Reset skip flag
                    skip_payload = False

                    arp_type = arp_match.group(1)
                    target_ip = arp_match.group(2)
                    sender_ip = arp_match.group(3)

                    # Skip localhost ARP unless -l is used
                    if not show_localhost and (
                        (sender_ip == "127.0.0.1" or sender_ip == machine_ip)
                    ):
                        skip_payload = True
                        continue

                    # Print ARP details
                    print(f"Type:     ARP {arp_type}")
                    print(f"Who has:  {target_ip}")
                    print(f"Tell:     {sender_ip}")
                    print(f"Length:   {protocol_length} bytes")
                    print("-" * 40)  # Separator between connections

                    # Prepare for potential payload
                    current_connection = {
                        "type": "ARP",
                        "arp_type": arp_type,
                        "target_ip": target_ip,
                        "sender_ip": sender_ip,
                    }
                    continue

            if conn_match:
                # If we have a previous payload, print it before starting new connection
                if payload_buffer and not skip_payload:
                    print("Payload:")
                    print("\n".join(payload_buffer))
                    print("-" * 40)
                    payload_buffer = []

                # Reset skip flag
                skip_payload = False

                src_ip = conn_match.group(1)
                src_port = conn_match.group(2)
                dst_ip = conn_match.group(3)
                dst_port = conn_match.group(4)
                flags = conn_match.group(5)

                # Skip localhost-to-localhost connections unless -l is used
                if not show_localhost and (
                    (src_ip == "127.0.0.1" or src_ip == machine_ip)
                ):
                    skip_payload = True
                    continue

                # Determine connection status
                connection_status = determine_connection_status(flags)

                # Apply filters
                if (
                    (filter_status and connection_status != filter_status)
                    or (filter_protocol and protocol != filter_protocol)
                    or (filter_flags and not all(f in flags for f in filter_flags))
                    or (filter_port and filter_port not in (src_port, dst_port))
                ):
                    skip_payload = True
                    continue

                # Print connection details
                print(f"IP:       {src_ip} -> {dst_ip}")
                print(f"Port:     {src_port} -> {dst_port}")
                print(f"Flags:    {interpret_flags(flags)}")
                print(f"Status:   {connection_status}")
                print(f"Protocol Length: {protocol_length} bytes")
                print(f"Total Length:    {total_length} bytes")
                print("-" * 40)  # Separator between connections

                # Prepare for potential payload
                current_connection = {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flags": flags,
                }

            # Check for payload data
            if show_payload and not skip_payload and line.startswith("\t0x"):
                # Preserve the full payload line
                payload_buffer.append(line.strip())

    except KeyboardInterrupt:
        # Print any remaining payload before exiting
        if payload_buffer and not skip_payload:
            print("Payload:")
            print("\n".join(payload_buffer))
            print("-" * 40)
        print("\nMonitoring stopped.")
    finally:
        tcpdump_process.terminate()
        tcpdump_process.wait()


# Run the monitoring
def main():
    parser = argparse.ArgumentParser(description="Monitor network connections")
    parser.add_argument(
        "-l",
        "--localhost",
        action="store_true",
        help="Show localhost-to-localhost connections",
    )
    parser.add_argument(
        "--status", help="Filter by connection status (e.g., 'Connection Attempt')"
    )
    parser.add_argument(
        "--flags", help="Filter by flags (comma-separated, e.g., 'S,.')"
    )
    parser.add_argument("--port", help="Filter by specific port")
    parser.add_argument(
        "--no-payload", action="store_true", help="Disable payload display"
    )

    args = parser.parse_args()

    # Process flags if provided
    filter_flags = args.flags.split(",") if args.flags else None

    monitor_connections(
        show_localhost=args.localhost,
        filter_status=args.status,
        filter_flags=filter_flags,
        filter_port=args.port,
        show_payload=not args.no_payload,
    )


if __name__ == "__main__":
    main()
