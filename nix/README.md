# Tailnet integration test

Run on Linux with writable `/dev/kvm`, from the repository root:

```sh
nix build ./nix#checks.x86_64-linux.tailnet -L
```

For just the headless package and focused Rust tests:

```sh
nix build ./nix#tailnet-test -L
```

`e2e.nix` imports Headscale's exported `testkit` and `testkit-peer` modules.
See the [kit contract](https://github.com/juanfont/headscale/blob/2d220b2eb8be8d31ed603000d0b0be02c2cd94d0/nix/README.md)
and the [upstream Rust example](https://github.com/tailscale/tailscale-rs/pull/445).
Headscale retains its own nixpkgs/Go pin. The Rust overlay is updated because
the vendored tailscale-rs requires Rust 1.92 or newer. The existing headless
package builds the CLI, mux, and its required `thinkterm-tailnet` child together.
The package check also runs the runtime library tests, including Linux network-monitor
initialization and TCP reply filtering.
Lucide and Simple Icons inputs match the repository gitlinks; both are required
by the headless CLI as well as the GUI.
The VM starts that mux as an ordinary user with no capabilities, no TUN,
`NoNewPrivileges`, and a read-only system. There is no existing ThinkTerm NixOS
service module; this unit is a test fixture, not a new deployment interface.

Only `tailnet-test` enables `thinkterm-tailnet/testkit`. This feature permits
plain HTTP control URLs and enables `ts_control/insecure-keyfetch` and
`ts_control/insecure-derp`. Shipping packages retain HTTPS validation and normal
DERP certificate verification. A separate test without the feature checks URL
validation. The kit's self-signed TLS endpoint serves control/DERP, not application
HTTPS. ThinkTerm's integration exposes no HTTPS listener.
Public ACME issuance and successful Tailscale Funnel are outside this local
fixture; neither is consumed by ThinkTerm's tailnet integration.

## Scope

The VM runs the real node rather than mocking its lifecycle. Assertions cover:

- Interactive authorization, invalid and reusable preauth keys, and encrypted
  persisted identity. Down/up, process crash, mux restart, and VM reboot preserve
  identity; logout forgets it and the next registration gets a new identity.
- Two processes sharing one identity under the node lock, takeover after the
  holder exits, keeper replacement after a crash, and in-process watchdog
  replacement while control is unavailable, followed by recovery. A control
  reconnect must deliver new policy without restarting the ThinkTerm process.
- Live peer discovery, short/FQDN/case-insensitive names, IPv4/IPv6 literals and
  family constraints. Unknown names and non-peer IPs cannot fall back to LAN DNS.
- Bidirectional binary TCP through the same Unix socket protocol used by the
  CLI, GUI, and mux. Both direct and forced-DERP peers carry application data;
  Go peer status verifies the path. Connection failures retain an allowed control.
- Outbound SSH transport; opt-in inbound forwarding to real OpenSSH on loopback,
  SSH key authentication and rejection, with forwarding off by default.
- Live network grants, tagged peers, and tagged ThinkTerm registration. A tagged
  node uses its tag's grant rather than its owner's grant. Denied SSH connections are checked
  alongside allowed TCP payloads, then restored when policy allows them again.
- Private settings/key/socket modes and cross-user socket rejection, including
  peer-credential enforcement after deliberately relaxing fixture filesystem modes.
- An unreachable replacement control URL cannot overwrite working settings.

ThinkTerm does not call WhoIs, interpret application capability grants, advertise
routes, or implement Tailscale SSH authorization. Inbound SSH is ordinary TCP
forwarding: sshd sees loopback and authenticates the SSH user. Network grants are
enforced by the embedded client/Go peer packet filters. Tags arrive through
preauth keys; ThinkTerm has no tag-management API.

Headscale cannot reproduce Tailscale SaaS cross-tailnet node sharing, its DNS
collision semantics, OAuth/SSO approval, or hosted control outages. Cross-tailnet
name preference remains covered only by the existing Rust unit tests. These VM
tests do not claim cloud integration coverage, GUI interaction, or macOS behavior.
