"""Continuous authorized capture. Payloads stay in bounded memory on this host."""
import argparse
import json
import random
import signal
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from secure_smtp.agent.observe import observe_stream
from secure_smtp.agent.outbox import Outbox
from secure_smtp.ingest.pcap_reader import PacketStream, StreamKey, _extract_packet
from secure_smtp.monitoring.schema import Heartbeat

PORTS = {25, 465, 587, 143, 993, 110, 995}


class Collector:
    def __init__(self, outbox):
        self.outbox, self.flows, self.lock = outbox, {}, threading.Lock()
        self.bytes = 0

    def receive(self, packet):
        raw = _extract_packet(packet, float(packet.time))
        if not raw or not ({raw.src_port, raw.dst_port} & PORTS):
            return
        key = StreamKey.from_packet(raw)
        with self.lock:
            if key in self.flows and 'S' in raw.flags and 'A' not in raw.flags:
                old = self.flows[key][0]
                # A fresh sequence number starts another connection on a reused tuple.
                if any('S' in p.flags and 'A' not in p.flags and p.seq != raw.seq for p in old.packets):
                    self.flush(key, complete=False)
            if key not in self.flows and len(self.flows) >= 512:
                self.outbox.increment('dropped_events')
                return
            stream, start, last = self.flows.get(key, (PacketStream(key), time.monotonic(), time.monotonic()))
            if len(stream.packets) >= 2048 or sum(len(p.payload) for p in stream.packets) + len(raw.payload) > 256 * 1024 or self.bytes + len(raw.payload) > 8 * 1024 * 1024:
                self.outbox.increment('capture_errors')
                self.flush(key, complete=False)
                return
            stream.packets.append(raw)
            self.bytes += len(raw.payload)
            self.flows[key] = (stream, start, time.monotonic())
            ends = {(p.src_ip, p.src_port) for p in stream.packets if 'F' in p.flags}
            if len(ends) >= 2 or 'R' in raw.flags:
                self.flush(key, complete=any('S' in p.flags and 'A' not in p.flags for p in stream.packets))

    def flush(self, key, complete=False):
        entry = self.flows.pop(key, None)
        if not entry:
            return
        stream = entry[0]
        self.bytes -= sum(len(p.payload) for p in stream.packets)
        try:
            observation = observe_stream(stream, complete)
            if observation:
                self.outbox.enqueue([observation])
        except Exception:
            self.outbox.increment('capture_errors')

    def expire(self, all_flows=False):
        with self.lock:
            for key, (_, start, last) in list(self.flows.items()):
                if all_flows or time.monotonic() - last > 30 or time.monotonic() - start > 120:
                    self.flush(key)


def deliver(client, base, token, outbox):
    item = outbox.oldest()
    if not item:
        return True
    batch_id, payload = item
    response = client.post(base + '/api/agents/ingest', content=payload,
                           headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    if response.is_success:
        result = response.json()
        if result.get('status') == 'done':
            outbox.acknowledge(batch_id)
            return True
    permanent = response.status_code in (410, 422)
    if response.status_code == 409:
        detail = response.json().get('detail', '')
        permanent = detail in ('Batch ID was already used with different observations',
                               'Event ID reused with different data')
    if permanent:
        # Permanently rejected observations cannot block subsequent batches indefinitely.
        outbox.increment('dropped_events', len(json.loads(payload)['observations']))
        outbox.acknowledge(batch_id)
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description='Authorized SMTP/IMAP/POP3 metadata collector')
    parser.add_argument('--server', required=True, help='HTTPS API origin')
    parser.add_argument('--interface', required=True)
    parser.add_argument('--credential-file', required=True, type=Path)
    parser.add_argument('--state', default='./agent-state/outbox.sqlite')
    parser.add_argument('--authorized', action='store_true', help='Confirm permission to capture on this interface')
    args = parser.parse_args()
    url = urlparse(args.server)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        parser.error('--server must be an HTTPS origin without credentials, path, or query')
    if not args.authorized:
        parser.error('Capture requires --authorized and permission from the network owner')
    if args.credential_file.stat().st_mode & 0o077:
        parser.error('Credential file permissions must be 0600 or stricter')
    token = args.credential_file.read_text().strip()
    if not token.startswith('sa_'):
        parser.error('Invalid agent credential file')
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *args: stop.set())
    outbox, base = Outbox(args.state), args.server.rstrip('/')
    collector = Collector(outbox)
    from scapy.all import AsyncSniffer
    sniffer = AsyncSniffer(iface=args.interface, filter='tcp and (port 25 or port 465 or port 587 or port 143 or port 993 or port 110 or port 995)', store=False, prn=collector.receive)
    sniffer.start()
    def heartbeat_loop():
        with httpx.Client(timeout=10, follow_redirects=False) as heartbeat_client:
            while not stop.is_set():
                health = outbox.health()
                status = Heartbeat(capture_active=bool(sniffer.running), **{k: health.get(k, 0) for k in ('queued_events', 'dropped_events', 'capture_errors')})
                try:
                    response = heartbeat_client.post(base + '/api/agents/heartbeat', json=status.model_dump(), headers={'Authorization': 'Bearer ' + token})
                    if response.status_code in (401, 403):
                        print('Agent access denied. Replace the credential; collection stopped.', flush=True)
                        stop.set()
                except httpx.HTTPError:
                    pass
                stop.wait(15)
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()
    delay, next_delivery = 1, 0
    failed_capture = False
    try:
        with httpx.Client(timeout=150, follow_redirects=False) as client:
            while not stop.wait(1):
                collector.expire()
                if not sniffer.running:
                    failed_capture = True
                    print('Capture stopped. Check interface permissions and restart the service.', flush=True)
                    break
                if time.monotonic() >= next_delivery:
                    try:
                        success = deliver(client, base, token, outbox)
                    except (httpx.HTTPError, ValueError):
                        success = False
                    delay = 1 if success else min(60, delay * 2)
                    next_delivery = time.monotonic() + delay + random.random()
    finally:
        stop.set()
        if sniffer.running:
            sniffer.stop()
        collector.expire(all_flows=True)
        heartbeat_thread.join(timeout=12)
        outbox.close()
    if failed_capture:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
