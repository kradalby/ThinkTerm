# Run from the repository root with KVM available:
# nix build ./nix#checks.x86_64-linux.tailnet -L
{
  pkgs,
  headscale,
  package,
}:
let
  peer = {
    imports = [ headscale.nixosModules.testkit-peer ];
    networking.firewall.trustedInterfaces = [ "tailscale0" ];
    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };
    environment.systemPackages = with pkgs; [
      jq
      python3
    ];
    # Two live listeners let a denied port be checked alongside an allowed one.
    systemd.services.echo = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.socat}/bin/socat TCP6-LISTEN:1234,ipv6only=0,reuseaddr,fork EXEC:${pkgs.coreutils}/bin/cat";
    };
  };
  policy =
    grants:
    pkgs.writeText "tailnet-policy.json" (
      builtins.toJSON {
        tagOwners."tag:server" = [ "operator@" ];
        tagOwners."tag:client" = [ "client@" ];
        inherit grants;
      }
    );
  allow = policy [
    {
      src = [ "*" ];
      dst = [ "*" ];
      ip = [ "*" ];
    }
  ];
  restricted = policy [
    {
      src = [ "client@" ];
      dst = [ "tag:server" ];
      ip = [ "tcp:1234" ];
    }
    {
      src = [ "operator@" ];
      dst = [ "client@" ];
      ip = [ "tcp:22" ];
    }
  ];
  tagged = policy [
    {
      src = [ "client@" ];
      dst = [ "tag:server" ];
      ip = [ "tcp:22" ];
    }
    {
      src = [ "tag:client" ];
      dst = [ "tag:server" ];
      ip = [ "tcp:1234" ];
    }
  ];
in
pkgs.testers.runNixOSTest {
  name = "thinkterm-tailnet";
  nodes = {
    headscale.imports = [ headscale.nixosModules.testkit ];
    direct.imports = [ peer ];
    relay = {
      imports = [ peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
    client = { ... }: {
      # Userspace WireGuard chooses an ephemeral UDP port. No TUN or capabilities.
      networking.firewall.enable = false;
      users.users.alice = {
        isNormalUser = true;
      };
      users.users.bob = {
        isNormalUser = true;
      };
      services.openssh = {
        enable = true;
        settings.PasswordAuthentication = false;
      };
      environment.systemPackages = with pkgs; [
        package
        python3
        jq
        openssh
        inotify-tools
      ];
      systemd.services.thinkterm = {
        wantedBy = [ "multi-user.target" ];
        environment = {
          HOME = "/home/alice";
          XDG_RUNTIME_DIR = "/run/thinkterm-test";
        };
        serviceConfig = {
          User = "alice";
          RuntimeDirectory = "thinkterm-test";
          RuntimeDirectoryMode = "0700";
          RuntimeDirectoryPreserve = true;
          ExecStart = "${package}/bin/thinkterm-mux-server --skip-config --no-initial-pane";
          NoNewPrivileges = true;
          CapabilityBoundingSet = "";
          ProtectSystem = "strict";
          ReadWritePaths = [ "/home/alice" ];
          PrivateTmp = true;
        };
      };
    };
  };
  testScript = ''
    ALLOW = "${allow}"
    RESTRICTED = "${restricted}"
    TAGGED = "${tagged}"
  ''
  + builtins.readFile ./e2e.py;
}
