import shlex

start_all()
client.wait_for_unit("thinkterm.service")
peer.wait_for_unit("echo.service")

# Generate disposable signing material inside the server guest.
headscale.succeed("""
install -d -m 0700 /run/fixture-pki
cd /run/fixture-pki
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ThinkTerm-fixture \
    -keyout ca.key -out ca.pem
openssl req -new -newkey rsa:2048 -nodes -subj /CN=headscale \
    -keyout server.key -out server.csr
printf 'subjectAltName=DNS:headscale\\nextendedKeyUsage=serverAuth\\n' > leaf.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 2 -extfile leaf.ext -out server.pem
install -D -m 0600 -o headscale server.key /var/lib/headscale/tls/server.key
install -m 0644 server.pem /var/lib/headscale/tls/server.pem
systemctl start headscale
""")
headscale.wait_for_unit("headscale.service")
ca = shlex.quote(headscale.succeed("cat /run/fixture-pki/ca.pem"))
for machine in (client, peer):
    machine.succeed(f"printf '%s' {ca} >/run/fixture-ca.pem")

peer_key = shlex.quote(headscale.succeed("hs-authkey peer").strip())
peer.succeed(
    "systemctl stop tailscaled; "
    "mkdir -p /run/systemd/system/tailscaled.service.d; "
    "printf '[Service]\\nEnvironment=SSL_CERT_FILE=/run/fixture-ca.pem\\n' "
    ">/run/systemd/system/tailscaled.service.d/fixture-ca.conf; "
    "systemctl daemon-reload; "
    "systemctl start tailscaled; "
    f"tailscale up --timeout=60s --login-server https://headscale --auth-key {peer_key} --hostname peer"
)

run = "runuser -u alice -- env XDG_RUNTIME_DIR=/run/thinkterm-test"
with subtest("desktop preflight rejects an untrusted certificate"):
    result = client.fail(
        f"{run} thinkterm tailnet up --control-url https://headscale 2>&1"
    )
    assert "TLS error" in result, result

with subtest("verified enrollment and peer discovery"):
    client_key = shlex.quote(headscale.succeed("hs-authkey client").strip())
    client.succeed(
        f"printf '%s\\n' {client_key} | {run} SSL_CERT_FILE=/run/fixture-ca.pem "
        "thinkterm tailnet up --control-url https://headscale --hostname thinkterm --auth-key-stdin"
    )
    client.wait_until_succeeds(
        f'{run} jq -e \'.status.state == "connected" and any(.peers[]; .name == "peer")\' '
        "/run/thinkterm-test/thinkterm/tailnet.json",
        timeout=90,
    )

with subtest("payload round trip through the ThinkTerm holder"):
    payload_probe = """
import json
import socket
from pathlib import Path

with socket.socket(socket.AF_UNIX) as sock:
    sock.settimeout(10)
    sock.connect(str(Path.home() / ".local/share/ThinkTerm/tailnet.sock"))
    request = {"host": "peer", "port": 1234, "family": "v4", "timeout_ms": 4000}
    sock.sendall((json.dumps(request) + "\\n").encode())
    with sock.makefile("rb") as stream:
        assert stream.readline() == b"ok\\n"
        payload = bytes(range(256)) * 256
        sock.sendall(payload)
        assert stream.read(len(payload)) == payload
"""
    client.wait_until_succeeds(
        f"{run} python3 -c {shlex.quote(payload_probe)}", timeout=90
    )
