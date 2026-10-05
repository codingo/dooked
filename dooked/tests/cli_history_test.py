"""Exercise the built CLI against a synthetic DNS server on loopback only."""
import datetime
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading

binary = pathlib.Path(sys.argv[1]).resolve()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(0.2)
port = sock.getsockname()[1]
answer_ip = "192.0.2.1"
stopping = threading.Event()


def serve():
    while not stopping.is_set():
        try:
            packet, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        end = 12
        while packet[end]:
            end += 1 + packet[end]
        end += 1
        kind = struct.unpack("!H", packet[end:end + 2])[0]
        question = packet[12:end + 4]
        answer = b""
        if kind == 1 and answer_ip:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip)
        header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
        sock.sendto(header + question + answer, peer)


thread = threading.Thread(target=serve, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        names = root / "names.txt"
        names.write_text("localhost\n")  # HTTP resolution also stays on loopback.

        def scan(source, output, *flags):
            result = subprocess.run([str(binary), "-i", str(source), "-o", str(output),
                                     "-r", f"127.0.0.1 {port}", "-t", "1", *flags],
                                    capture_output=True, text=True, timeout=45)
            assert result.returncode == 0, result.stdout + result.stderr
            return result, json.loads(output.with_suffix(".json").read_text())

        first_run, first = scan(names, root / "first", "--fs")
        assert "[FIRST-SEEN]" in first_run.stdout
        old = first["result"][0]["localhost"]["dns_probe"][0]
        assert old["seen"] == 1 and old["first-seen"] == old["last-seen"]
        answer_ip = "192.0.2.2"
        second_run, second = scan(root / "first.json", root / "second", "--fs", "--ls", "0")
        records = {r["info"]: r for r in second["result"][0]["localhost"]["dns_probe"]}
        assert len(records) == 2 and records["192.0.2.1"]["observed"] is False
        assert "[FIRST-SEEN]" in second_run.stdout and "[LAST-SEEN]" in second_run.stdout
        answer_ip = "192.0.2.1"
        third_run, third = scan(root / "second.json", root / "third", "--fs", "--silent")
        assert "[FIRST-SEEN]" not in third_run.stdout and "[LAST-SEEN]" not in third_run.stdout
        records = {r["info"]: r for r in third["result"][0]["localhost"]["dns_probe"]}
        assert records["192.0.2.1"]["seen"] == 2
        assert records["192.0.2.1"]["first-seen"] == old["first-seen"]
        answer_ip = None
        _, absent = scan(root / "third.json", root / "absent", "--ls", "0")
        assert len(absent["result"][0]["localhost"]["dns_probe"]) == 2
        for r in absent["result"][0]["localhost"]["dns_probe"]:
            r["first-seen"] = 100
            r["last-seen"] = 200
        (root / "aged.json").write_text(json.dumps(absent))
        aged_run, _ = scan(root / "aged.json", root / "aged-output", "--ls", "2", "--lsd", "01/02/1970")
        assert "[LAST-SEEN]" in aged_run.stdout
        for flags in [("--ls", "-1"), ("--lsd", "02/30/2026")]:
            invalid = subprocess.run([str(binary), *flags], capture_output=True, timeout=5)
            assert invalid.returncode != 0, flags
        print("PASS: real CLI flags, rotation/reappearance, persistence, silent mode, age/date reports, invalid arguments")
finally:
    stopping.set()
    thread.join(timeout=2)
    sock.close()
