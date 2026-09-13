"""Bounded, fresh-connection HTTP observations; never retry a failed sample."""

import argparse
import ipaddress
import json
import socket
import time


def validate_targets(targets):
    if not isinstance(targets, list) or len(targets) != 8:
        raise ValueError("exactly eight locality/address targets required")
    labels = set()
    for target in targets:
        label = target["label"]
        if not isinstance(label, str) or not label or label in labels:
            raise ValueError("unique nonempty target labels required")
        labels.add(label)
        ipaddress.ip_address(target["address"])
        if type(target["port"]) is not int or target["port"] not in (8080, 18080):
            raise ValueError("fixture backend or translated HTTP port required")
    return targets


def observe(target):
    started = time.monotonic()
    record = {"type": "sample", "label": target["label"], "unixMs": time.time_ns() // 1_000_000}
    try:
        with socket.create_connection((target["address"], target["port"]), timeout=0.5) as connection:
            deadline = started + 1.0
            connection.sendall(b"GET / HTTP/1.0\r\nHost: fixture\r\nConnection: close\r\n\r\n")
            header = b""
            while b"\r\n" not in header and len(header) < 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("bounded response deadline exceeded")
                connection.settimeout(min(0.5, remaining))
                data = connection.recv(1024 - len(header))
                if not data:
                    break
                header += data
            status = header.split(b"\r\n", 1)[0].split()
            record["ok"] = b"\r\n" in header and len(status) >= 2 and status[0] in (b"HTTP/1.0", b"HTTP/1.1") and status[1] == b"200"
            record["outcome"] = "http-200" if record["ok"] else "invalid-http-response"
    except OSError as error:
        record.update(ok=False, outcome=type(error).__name__)
    record["elapsedMs"] = round((time.monotonic() - started) * 1000, 3)
    return record


def emit(record):
    print(json.dumps(record, separators=(",", ":")), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", required=True)
    parser.add_argument("--seconds", type=int, default=45, choices=range(30, 61))
    args = parser.parse_args()
    targets = validate_targets(json.loads(args.targets))
    emit({"type": "started", "unixMs": time.time_ns() // 1_000_000, "targets": targets})
    deadline = time.monotonic() + args.seconds
    samples = failures = 0
    while time.monotonic() < deadline:
        for target in targets:
            record = observe(target)
            emit(record)
            samples += 1
            failures += not record["ok"]
        time.sleep(0.2)
    emit({"type": "complete", "unixMs": time.time_ns() // 1_000_000, "samples": samples, "failures": failures})
    # Transport observation completes even when packets failed. The parent must
    # validate the records and reject any failed sample, not trust exit zero.


if __name__ == "__main__":
    main()
