#!/usr/bin/env python3
"""
Secure SMTP — Live Client Demonstration Tool.

Zero-dependency script designed to run from any device on the local network
(e.g., friend's laptop, phone, secondary computer) to demonstrate live
cross-device SMTP security inspection and cryptographic posture attribution.

Usage:
    python demo_client.py --server 192.168.1.40 --port 2525
    python demo_client.py --server 192.168.1.40 --scenario stripped
    python demo_client.py (interactive menu mode)
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"\n{CYAN}{BOLD}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║         SECURE SMTP — LIVE CROSS-DEVICE MAIL CLIENT        ║{RESET}")
    print(f"{CYAN}{BOLD}║   Zero-Cloud LAN Socket Injector for Real-Time Detections   ║{RESET}")
    print(f"{CYAN}{BOLD}╚════════════════════════════════════════════════════════════╝{RESET}\n")


def send_raw_smtp(
    host: str,
    port: int,
    use_tls: bool = False,
    expect_stripping: bool = False,
    sender: str = "alice@friend-laptop.local",
    recipient: str = "bob@securesmtp.local",
    subject: str = "Live Cross-Device Mail Demonstration",
    body: str = "Confidential project update transmitted across local network.",
) -> bool:
    """Send an SMTP session over a raw TCP socket with optional STARTTLS."""
    print(f"{YELLOW}[*] Connecting to {host}:{port}...{RESET}")
    try:
        s = socket.create_connection((host, port), timeout=6)
    except Exception as e:
        print(f"{RED}[!] Connection failed: {e}{RESET}")
        print(f"{YELLOW}[*] Hint: Ensure both laptops are on the same Wi-Fi network and firewall allows port {port}.{RESET}")
        return False

    def send_cmd(cmd: str) -> str:
        s.sendall(cmd.encode("utf-8") + b"\r\n")
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        return resp.strip()

    try:
        banner = s.recv(4096).decode("utf-8", errors="ignore").strip()
        print(f"  {CYAN}<< {banner}{RESET}")

        helo_resp = send_cmd("EHLO friend-laptop.local")
        print(f"  {GREEN}>> EHLO friend-laptop.local{RESET}")
        print(f"  {CYAN}<< {helo_resp}{RESET}")

        if use_tls:
            print(f"  {GREEN}>> STARTTLS{RESET}")
            tls_resp = send_cmd("STARTTLS")
            print(f"  {CYAN}<< {tls_resp}{RESET}")

            if expect_stripping:
                print(f"  {RED}[!] Server rejected STARTTLS or stripped capability! (Tampering detected){RESET}")
                # Fall back to plaintext transmission to demonstrate leakage
            elif "220" in tls_resp:
                # Wrap socket with TLS
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers("DEFAULT@SECLEVEL=0")
                except Exception:
                    pass
                s = ctx.wrap_socket(s, server_hostname="mail.securesmtp.local")
                print(f"  {GREEN}[✓] TLS Handshake negotiated successfully! ({s.version()}, {s.cipher()[0]}){RESET}")

                # Send post-TLS EHLO
                s.sendall(b"EHLO friend-laptop.local\r\n")
                s.recv(4096)

        # Mail envelope
        send_cmd(f"MAIL FROM:<{sender}>")
        send_cmd(f"RCPT TO:<{recipient}>")
        send_cmd("DATA")

        email_data = (
            f"From: {sender}\r\n"
            f"To: {recipient}\r\n"
            f"Subject: {subject}\r\n"
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
            f"\r\n"
            f"{body}\r\n"
            f".\r\n"
        )
        s.sendall(email_data.encode("utf-8"))
        data_resp = s.recv(4096).decode("utf-8", errors="ignore").strip()
        print(f"  {CYAN}<< {data_resp}{RESET}")

        send_cmd("QUIT")
        print(f"{GREEN}[✓] Session completed! Telemetry recorded and broadcasted.{RESET}")
        return True

    except Exception as e:
        print(f"{YELLOW}[!] Notice during session dialogue: {e}{RESET}")
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_interactive(default_host: str):
    print(f"{CYAN}Target Server Configuration:{RESET}")
    entered_ip = input(f"Enter Secure SMTP Server LAN IP [{default_host}]: ").strip()
    host = entered_ip if entered_ip else default_host

    while True:
        print(f"\nTarget Server: {GREEN}{BOLD}{host}{RESET}")
        print("Select a live test scenario to transmit:")
        print(f"  {BOLD}1{RESET}) ⚪ Plaintext Port 2525 (No TLS) -> Triggers 'no-tls' (Critical 80+ Risk)")
        print(f"  {BOLD}2{RESET}) 🟢 Modern TLS 1.3 Baseline (Port 2526) -> Clean Hardened Session (Risk 0)")
        print(f"  {BOLD}3{RESET}) 🟡 Expired Certificate & Weak Key (Port 2527) -> Triggers 'cert-expired' (High Risk)")
        print(f"  {BOLD}4{RESET}) 🔴 STARTTLS Stripping Attack (Port 2528) -> Triggers 'starttls-stripped' (Critical 95+ Risk)")
        print(f"  {BOLD}5{RESET}) 🔄 Continuous Demo Loop (Alternates scenarios every 6 seconds)")
        print(f"  {BOLD}q{RESET}) Quit")

        choice = input(f"\nEnter choice [1-5, q] (default 1): ").strip().lower() or "1"

        if choice == "q":
            print("\nExiting. Happy demoing!\n")
            break
        elif choice == "1":
            print(f"\n{BOLD}--> Dispatching Plaintext SMTP to {host}:2525...{RESET}")
            send_raw_smtp(host, 2525, use_tls=False)
        elif choice == "2":
            print(f"\n{BOLD}--> Dispatching Hardened Modern TLS 1.3 to {host}:2526...{RESET}")
            send_raw_smtp(host, 2526, use_tls=True)
        elif choice == "3":
            print(f"\n{BOLD}--> Dispatching Vulnerable/Expired TLS to {host}:2527...{RESET}")
            send_raw_smtp(host, 2527, use_tls=True)
        elif choice == "4":
            print(f"\n{BOLD}--> Dispatching STARTTLS Stripping Tampering to {host}:2528...{RESET}")
            send_raw_smtp(host, 2528, use_tls=True, expect_stripping=True)
        elif choice == "5":
            print(f"\n{BOLD}--> Starting continuous traffic loop to {host}. Press Ctrl+C to stop.{RESET}")
            scenarios = [
                (2528, True, True, "STARTTLS Stripping Attack"),
                (2526, True, False, "Modern TLS 1.3 Clean Baseline"),
                (2525, False, False, "Plaintext Leakage"),
                (2527, True, False, "Expired Certificate"),
            ]
            idx = 0
            try:
                while True:
                    p, tls, strip, name = scenarios[idx % len(scenarios)]
                    print(f"\n[{idx+1}] Injecting: {name} (Port {p})")
                    send_raw_smtp(host, p, use_tls=tls, expect_stripping=strip)
                    idx += 1
                    time.sleep(5)
            except KeyboardInterrupt:
                print("\nContinuous loop stopped.")
        else:
            print(f"{RED}Invalid choice.{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Secure SMTP Live Client Tool")
    parser.add_argument("--server", default="192.168.0.155", help="Target Secure SMTP Server IP (default: 192.168.0.155)")
    parser.add_argument("--port", type=int, default=None, help="Target Port (2525, 2526, 2527, 2528)")
    parser.add_argument("--scenario", choices=["plaintext", "tls", "vulnerable", "stripped"], help="Automated scenario")
    args = parser.parse_args()

    print_banner()

    if args.port:
        use_tls = args.port in (2526, 2527, 2528)
        expect_stripping = args.port == 2528
        send_raw_smtp(args.server, args.port, use_tls=use_tls, expect_stripping=expect_stripping)
    elif args.scenario == "plaintext":
        send_raw_smtp(args.server, 2525, use_tls=False)
    elif args.scenario == "tls":
        send_raw_smtp(args.server, 2526, use_tls=True)
    elif args.scenario == "vulnerable":
        send_raw_smtp(args.server, 2527, use_tls=True)
    elif args.scenario == "stripped":
        send_raw_smtp(args.server, 2528, use_tls=True, expect_stripping=True)
    else:
        run_interactive(args.server)


if __name__ == "__main__":
    main()

