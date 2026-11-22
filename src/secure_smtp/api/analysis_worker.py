"""Bounded worker that cannot outlive its supervising API process."""

import os
import sys
import threading
import time

from secure_smtp.api.pipeline import run_pcap_analysis


def supervise(parent):
    while True:
        if os.getppid() != parent:
            os._exit(1)
        time.sleep(0.2)


if __name__ == "__main__":
    parent = int(sys.argv[3])
    if os.getppid() != parent:
        sys.exit(1)
    threading.Thread(target=supervise, args=(parent,), daemon=True).start()
    run_pcap_analysis(sys.argv[1], sys.argv[2])
