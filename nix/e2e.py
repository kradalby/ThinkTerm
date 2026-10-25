import json
import shlex

T = 180
DATA = "/home/alice/.local/share/ThinkTerm"
REPORT = "/run/thinkterm-test/thinkterm/tailnet.json"
SOCKET = DATA + "/tailnet.sock"


def as_user(command, user="alice"):
    return (
        f"runuser -u {user} -- env XDG_RUNTIME_DIR=/run/thinkterm-test "
        f"sh -c {shlex.quote(command)}"
    )


def cli(args, key=None, ok=True):
    command = "thinkterm tailnet " + args
    if key is not None:
        command = f"printf '%s\\n' {shlex.quote(key)} | {command} --auth-key-stdin"
    return (client.succeed if ok else client.fail)(as_user(command))


def report():
    return json.loads(client.succeed(f"cat {REPORT}"))


def connected():
    client.wait_until_succeeds(
        f"jq -e '.status.state == \"connected\"' {REPORT}", timeout=T
    )
    return report()


def probe(host, port=1234, family="any", expected="ok", user="alice"):
    # Use the same socket protocol as other ThinkTerm processes. The payload must
    # make a round trip: a successful TCP handshake alone proves too little.
    request = (
        json.dumps({"host": host, "port": port, "family": family, "timeout_ms": 4000})
        + "\n"
    )
    script = f"""
import socket
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(10)
    s.connect({SOCKET!r})
    s.sendall({request.encode()!r})
    answer = b''
    while not answer.endswith(b'\\n'):
        part = s.recv(1)
        assert part, answer
        answer += part
    expected = {expected!r}
    if expected == 'error':
        assert answer.startswith(b'error: '), answer
    else:
        assert answer == (expected + '\\n').encode(), answer
    if expected == 'ok':
        if {port} == 22:
            banner = b''
            while len(banner) < 8:
                part = s.recv(8 - len(banner))
                assert part, 'missing SSH banner'
                banner += part
            assert banner == b'SSH-2.0-', banner
        else:
            payload = bytes(range(256)) * 256
            s.sendall(payload)
            got = b''
            while len(got) < len(payload):
                part = s.recv(len(payload) - len(got))
                assert part, len(got)
                got += part
            assert got == payload
"""
    return as_user("python3 -c " + shlex.quote(script), user)


def traffic(host):
    client.wait_until_succeeds(probe(host), timeout=T)


def control_outage():
    pid = connected()["pid"]
    inode = client.succeed(f"stat -c %i {SOCKET}")
    log = f"/run/thinkterm-test/thinkterm/thinkterm-tailnet-log-{pid}.txt"
    offset = int(client.succeed(f"stat -c %s {log}"))
    headscale.succeed("systemctl stop headscale")
    # An immediate probe can race the old actor. Require its end and a replacement's failed dial.
    restarted = f"""from pathlib import Path
with Path({log!r}).open('rb') as log:
    log.seek({offset})
    events = log.read()
ended = events.find(b'state update stream terminated')
assert ended >= 0, events
assert b'control dial failed; retrying' in events[ended:], events
assert b'starting the node anew' not in events, events
"""
    client.wait_until_succeeds("python3 -c " + shlex.quote(restarted), timeout=T)
    client.wait_until_succeeds(
        f"jq -e '.pid == {pid} and .status.state == \"starting\"' {REPORT}",
        timeout=T,
    )
    for family in ("v4", "v6"):
        client.succeed(probe("direct", family=family))
    headscale.fail("systemctl is-active headscale")
    assert report()["pid"] == pid
    assert report()["status"]["state"] == "starting"
    assert client.succeed(f"stat -c %i {SOCKET}") == inode
    client.succeed("python3 -c " + shlex.quote(restarted))


def ssh_command(ip):
    return (
        "ssh -i /tmp/id -o BatchMode=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@{ip} "
        "'printf ssh-ok' | grep -x ssh-ok"
    )


start_all()
client.wait_for_unit("thinkterm.service")
for machine in (direct, relay):
    machine.wait_for_unit("echo.service")
    machine.wait_for_unit("sshd.service")
headscale.succeed("hs-authkey client")
headscale.succeed("hs-authkey operator")
headscale.succeed(f"headscale policy set -f {ALLOW}")
tagged_key = headscale.succeed("hs-authkey operator --tags tag:server").strip()
direct.succeed(f"hs-join {tagged_key} --hostname direct")
relay.succeed(f"hs-join {tagged_key} --hostname relay")

with subtest("interactive authorization and live peer discovery"):
    client.succeed(
        as_user(
            "thinkterm tailnet up --control-url http://headscale --hostname thinkterm > /home/alice/join.log 2>&1 &"
        )
    )
    client.wait_until_succeeds(
        f"jq -e '.status.state == \"needs_login\"' {REPORT}", timeout=T
    )
    auth_id = report()["status"]["url"].rstrip("/").split("/")[-1]
    headscale.succeed(
        f"headscale auth register --user client --auth-id {shlex.quote(auth_id)}"
    )
    initial = connected()
    client.wait_until_succeeds(f"jq -e '.peers | length == 2' {REPORT}", timeout=T)
    peers = {p["name"]: p for p in report()["peers"]}
    assert set(peers) == {"direct", "relay"}, peers
    for peer in peers.values():
        assert peer["fqdn"].endswith(".tailnet"), peer
        assert peer["ipv4"] and peer["ipv6"], peer
    ip = initial["status"]["address"]
    node_count = len(json.loads(headscale.succeed("headscale nodes list -o json")))
    assert node_count == 3

with subtest("direct and forced-DERP application traffic"):
    # Rust path discovery starts with outbound application traffic.
    traffic("direct")
    direct.wait_until_succeeds(
        'tailscale status --json | jq -e \'.Peer[] | select(.HostName == "thinkterm") | (.CurAddr // "") != ""\'',
        timeout=T,
    )
    traffic("direct")
    relay.wait_until_succeeds(
        'tailscale status --json | jq -e \'.Peer[] | select(.HostName == "thinkterm") | .Relay == "headscale"\'',
        timeout=T,
    )
    traffic("relay")
    relay.succeed(
        'tailscale status --json | jq -e \'.Peer[] | select(.HostName == "thinkterm") | (.CurAddr // "") == ""\''
    )
    for host in ("DIRECT.TAILNET.", peers["direct"]["ipv4"], peers["direct"]["ipv6"]):
        client.succeed(probe(host))
    client.succeed(probe("relay", family="v6"))
    for host in (
        "localhost",
        "headscale",
        "example.invalid",
        "127.0.0.1",
        "192.168.1.1",
    ):
        client.succeed(probe(host, expected="none"))
    client.succeed(probe(peers["direct"]["ipv4"], family="v6", expected="none"))
    client.succeed(probe("direct", port=65432, expected="error"))
    traffic("direct")

with subtest("SSH forwarding is opt-in; outbound SSH stays available"):
    for machine in (direct, relay):
        client.succeed(probe(machine.name, port=22))
        machine.fail(
            f"timeout 8 bash -c 'exec 3<>/dev/tcp/{ip}/22; read -r -t 5 line <&3; [[ $line == SSH-2.0-* ]]'"
        )
        client.succeed(probe(machine.name, port=22))
    cli("up --serve-ssh")
    connected()
    # Authenticate against the real sshd, not Tailscale SSH or an echo fixture.
    direct.succeed("ssh-keygen -q -t ed25519 -N '' -f /tmp/id")
    public_key = direct.succeed("cat /tmp/id.pub").strip()
    client.succeed("mkdir -p /root/.ssh; chmod 700 /root/.ssh")
    client.succeed(
        f"printf '%s\\n' {shlex.quote(public_key)} > /root/.ssh/authorized_keys"
    )
    # OpenSSH uses the node's local proxy exactly as another process would.
    proxy = r"""import json, socket, sys, threading
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect("/home/alice/.local/share/ThinkTerm/tailnet.sock")
s.sendall((json.dumps({"host": sys.argv[1], "port": int(sys.argv[2]), "timeout_ms": 5000}) + "\n").encode())
answer = b""
while not answer.endswith(b"\n"):
    part = s.recv(1)
    assert part, answer
    answer += part
assert answer == b"ok\n", answer
s.settimeout(None)
def send():
    while data := sys.stdin.buffer.read1(65536):
        s.sendall(data)
    s.shutdown(socket.SHUT_WR)
threading.Thread(target=send, daemon=True).start()
while data := s.recv(65536):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
"""
    client.succeed(f"printf '%s' {shlex.quote(proxy)} > /home/alice/proxy.py")
    for machine in (direct, relay):
        machine.succeed("mkdir -p /root/.ssh; chmod 700 /root/.ssh")
        machine.succeed(
            f"printf '%s\\n' {shlex.quote(public_key)} > /root/.ssh/authorized_keys"
        )
    private_key = direct.succeed("cat /tmp/id")
    client.succeed(
        f"printf '%s' {shlex.quote(private_key)} > /home/alice/id; chown alice /home/alice/id; chmod 600 /home/alice/id"
    )
    for host in ("direct", "relay"):
        client.succeed(
            as_user(
                f"ssh -i /home/alice/id -o BatchMode=yes -o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "
                f"-o 'ProxyCommand=python3 /home/alice/proxy.py %h %p' root@{host} "
                "'printf outbound-ssh' | grep -x outbound-ssh"
            )
        )
    relay.succeed(
        f"printf '%s' {shlex.quote(private_key)} > /tmp/id; chmod 600 /tmp/id"
    )
    for machine in (direct, relay):
        machine.wait_until_succeeds(ssh_command(ip), timeout=T)
    direct.succeed("ssh-keygen -q -t ed25519 -N '' -f /tmp/wrong")
    direct.fail(ssh_command(ip).replace("/tmp/id", "/tmp/wrong"))
    direct.succeed(ssh_command(ip))

with subtest("live grants and tags enforce denial with allowed controls"):
    headscale.succeed(f"headscale policy set -f {RESTRICTED}")
    for host in ("direct", "relay"):
        client.wait_until_succeeds(probe(host, port=22, expected="error"), timeout=T)
        traffic(host)
        client.succeed(probe(host, port=22, expected="error"))
    # Tagged peers are no longer operator@, so their inbound SSH is denied.
    for machine in (direct, relay):
        machine.wait_until_fails(ssh_command(ip), timeout=T)
        traffic(machine.name)
        machine.fail(ssh_command(ip))
    headscale.succeed(f"headscale policy set -f {ALLOW}")
    for machine in (direct, relay):
        machine.wait_until_succeeds(ssh_command(ip), timeout=T)
        client.wait_until_succeeds(probe(machine.name, port=22), timeout=T)

with subtest("private shared identity and socket credentials"):
    client.succeed(
        f"test $(stat -c %a {DATA}) = 700 && test $(stat -c %a {SOCKET}) = 600"
    )
    client.succeed(
        f"test $(stat -c %a {DATA}/tailnet.json) = 600 && test $(stat -c %a {DATA}/secret.key) = 600"
    )
    client.succeed(f"jq -e '.node_keys | startswith(\"enc:v1:\")' {DATA}/tailnet.json")
    client.succeed(f"test $(stat -c %a {REPORT}) = 600")
    client.fail(as_user(f"cat {REPORT}", "bob"))
    client.fail(as_user(f"cat {DATA}/tailnet.json", "bob"))
    client.fail(probe("direct", user="bob"))
    traffic("direct")
    # Allow traversal, not directory listing, so the second rejection can only
    # come after connect succeeds. The server silently closes foreign-UID peers.
    ancestors = ["/home/alice", "/home/alice/.local", "/home/alice/.local/share", DATA]
    client.succeed(as_user("test -x / && test -x /home", "bob"))
    modes = {
        path: int(client.succeed(f"stat -c %a {path}"), 8)
        for path in ancestors + [SOCKET]
    }
    try:
        for path in ancestors:
            client.succeed(f"chmod {modes[path] | 0o111:o} {path}")
        client.succeed(f"chmod 666 {SOCKET}")
        rejected = f"""import socket
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(2)  # Authorized idle connections wait five seconds for a request.
    s.connect({SOCKET!r})
    print("connected as Bob")
    # No malformed request or timeout can stand in for UID rejection: the node
    # closes an unauthorized connection before reading any request bytes.
    try:
        assert s.recv(1) == b"", "foreign UID received application data"
    except ConnectionResetError:
        pass
    print("foreign UID rejected after connect")
"""
        output = client.succeed(as_user("python3 -c " + shlex.quote(rejected), "bob"))
        assert "connected as Bob" in output
        assert "foreign UID rejected after connect" in output
        traffic("direct")
    finally:
        for path, mode in modes.items():
            client.succeed(f"chmod {mode:o} {path}")
    holder = connected()["pid"]
    client.succeed(
        "systemd-run --unit=contender --uid=alice --setenv=HOME=/home/alice "
        "--setenv=XDG_RUNTIME_DIR=/run/thinkterm-test thinkterm-tailnet --parent 1"
    )
    client.wait_for_unit("contender.service")
    client.sleep(5)
    assert connected()["pid"] == holder
    traffic("direct")
    client.succeed("systemctl is-active contender")
    contender = int(client.succeed("systemctl show contender -p MainPID --value"))
    client.succeed("systemctl stop thinkterm")
    client.wait_until_succeeds(
        f"jq -e '.pid == {contender} and .status.state == \"connected\"' {REPORT}",
        timeout=T,
    )
    assert connected()["status"]["address"] == ip
    traffic("relay")
    client.succeed("systemctl start thinkterm")
    client.succeed("systemctl stop contender")
    client.wait_until_succeeds(
        f"jq -e '.pid != {contender} and .status.state == \"connected\"' {REPORT}",
        timeout=T,
    )
    traffic("direct")

with subtest("keeper replaces a crashed node using persisted identity"):
    holder = connected()["pid"]
    client.succeed(f"kill -KILL {holder}")
    client.wait_until_succeeds(
        f"jq -e '.pid != {holder} and .status.state == \"connected\"' {REPORT}",
        timeout=T,
    )
    assert connected()["status"]["address"] == ip
    traffic("direct")
    traffic("relay")
    client.succeed("systemctl restart thinkterm")
    connected()
    traffic("relay")
    assert connected()["status"]["address"] == ip

with subtest("reboot keeps the same identity without an auth key"):
    client.shutdown()
    client.start()
    client.wait_for_unit("thinkterm.service")
    connected()
    assert connected()["status"]["address"] == ip
    traffic("direct")
    traffic("relay")
    assert (
        len(json.loads(headscale.succeed("headscale nodes list -o json"))) == node_count
    )

with subtest("unreachable replacement control leaves working settings intact"):
    before = client.succeed(f"sha256sum {DATA}/tailnet.json")
    cli("up --control-url http://127.0.0.1:9", ok=False)
    assert client.succeed(f"sha256sum {DATA}/tailnet.json") == before
    traffic("relay")

with subtest("control reconnect delivers new policy without a process restart"):
    pid = connected()["pid"]
    for machine in (direct, relay):
        machine.succeed(ssh_command(ip))
    control_outage()
    headscale.succeed("systemctl start headscale")
    headscale.wait_until_succeeds("headscale health", timeout=T)
    headscale.succeed(f"headscale policy set -f {RESTRICTED}")
    client.wait_until_succeeds(probe("direct", port=22, expected="error"), timeout=T)
    traffic("direct")
    # Only ThinkTerm's refreshed inbound filter can reject these tagged peers.
    for machine in (direct, relay):
        machine.wait_until_fails(ssh_command(ip), timeout=T)
        traffic(machine.name)
        machine.fail(ssh_command(ip))
    assert connected()["pid"] == pid
    headscale.succeed(f"headscale policy set -f {ALLOW}")
    for machine in (direct, relay):
        machine.wait_until_succeeds(ssh_command(ip), timeout=T)
    client.wait_until_succeeds(probe("direct", port=22), timeout=T)
    traffic("relay")
    assert connected()["pid"] == pid
    assert connected()["status"]["address"] == ip

with subtest("control outage and watchdog recovery"):
    control_outage()
    # Start a persisted node while control is unavailable; recovery must not need
    # a settings change, a new auth key, or another process restart.
    client.succeed("systemctl restart thinkterm")
    client.wait_until_succeeds(
        f"jq -e '.status.state != \"connected\"' {REPORT}", timeout=T
    )
    client.wait_until_succeeds(f"test -S {SOCKET}", timeout=T)
    waiting_pid = report()["pid"]
    client.succeed(
        f"inotifywait -t 90 -e delete_self {SOCKET} > /tmp/watchdog-event 2>&1 &"
    )
    client.wait_until_succeeds("grep -F DELETE_SELF /tmp/watchdog-event", timeout=100)
    assert report()["pid"] == waiting_pid
    client.succeed(
        f"grep -F 'starting the node anew' /run/thinkterm-test/thinkterm/thinkterm-tailnet-log-{waiting_pid}.txt"
    )
    headscale.succeed("systemctl start headscale")
    recovered = connected()
    assert recovered["pid"] == waiting_pid, recovered
    assert recovered["status"]["address"] == ip
    traffic("direct")
    traffic("relay")
    assert connected()["pid"] == waiting_pid

with subtest("down preserves identity; logout replaces it; bad keys fail"):
    holder = connected()["pid"]
    cli("down")
    client.wait_until_fails(f"kill -0 {holder}", timeout=30)
    client.wait_until_fails(f"test -S {SOCKET}", timeout=30)
    cli("up")
    assert connected()["status"]["address"] == ip
    traffic("relay")
    cli("logout")
    client.wait_until_fails(f"test -S {SOCKET}", timeout=30)
    client.succeed(
        f'jq -e \'has("node_keys") == false and has("auth_key") == false\' {DATA}/tailnet.json'
    )
    failure = cli("up", key="tskey-auth-invalid", ok=False)
    assert "signing in failed:" in failure, failure
    assert report()["status"]["state"] != "connected"
    headscale.succeed("headscale health")
    direct.succeed("tailscale ping --until-direct=false -c 1 --timeout 5s relay")
    key = headscale.succeed("hs-authkey client").strip()
    cli("up --hostname ''", key=key)
    new = connected()
    assert new["status"]["address"] != ip
    assert new["status"]["name"].startswith("thinkterm-")
    client.succeed(f"jq -e '.auth_key | startswith(\"enc:v1:\")' {DATA}/tailnet.json")
    traffic("direct")
    traffic("relay")

with subtest("saving a new auth key does not restart a connected node"):
    pid = connected()["pid"]
    inode = client.succeed(f"stat -c %i {SOCKET}")
    cli("up", key=headscale.succeed("hs-authkey client").strip())
    assert connected()["pid"] == pid
    assert client.succeed(f"stat -c %i {SOCKET}") == inode
    traffic("relay")
    assert (
        len(json.loads(headscale.succeed("headscale nodes list -o json")))
        == node_count + 1
    )

with subtest("tagged auth keys replace the user's network identity"):
    cli("logout")
    client.wait_until_fails(f"test -S {SOCKET}", timeout=30)
    key = headscale.succeed("hs-authkey client --tags tag:client").strip()
    cli("up --hostname tagged", key=key)
    connected()
    direct.wait_until_succeeds(
        'tailscale status --json | jq -e \'.Peer[] | select(.HostName == "tagged") | .Tags | index("tag:client")\'',
        timeout=T,
    )
    # The owner's grant permits SSH, but a tagged node must use the tag grant.
    headscale.succeed(f"headscale policy set -f {TAGGED}")
    for host in ("direct", "relay"):
        client.wait_until_succeeds(probe(host, port=22, expected="error"), timeout=T)
        traffic(host)
        client.succeed(probe(host, port=22, expected="error"))
    headscale.succeed(f"headscale policy set -f {ALLOW}")
    for host in ("direct", "relay"):
        client.wait_until_succeeds(probe(host, port=22), timeout=T)
