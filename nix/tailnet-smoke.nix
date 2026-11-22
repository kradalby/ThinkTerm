{
  pkgs,
  headscale,
  package,
}:
pkgs.testers.runNixOSTest {
  name = "thinkterm-tailnet";
  nodes = {
    headscale =
      { lib, ... }:
      {
        imports = [ headscale.nixosModules.testkit ];
        services.headscale.settings = {
          server_url = lib.mkForce "https://headscale";
          listen_addr = lib.mkForce "[::]:443";
          tls.cert_path = "/var/lib/headscale/tls/server.pem";
          tls.key_path = "/var/lib/headscale/tls/server.key";
        };
        systemd.services.headscale = {
          wantedBy = lib.mkForce [ ];
          environment.HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR = lib.mkForce null;
        };
        environment.systemPackages = [ pkgs.openssl ];
      };
    peer = {
      imports = [ headscale.nixosModules.testkit-peer ];
      networking.firewall.interfaces.tailscale0.allowedTCPPorts = [ 1234 ];
      systemd.services.echo = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.socat}/bin/socat TCP-LISTEN:1234,reuseaddr,fork EXEC:${pkgs.coreutils}/bin/cat";
      };
    };
    client = {
      users.users.alice.isNormalUser = true;
      environment.systemPackages = [
        package
        pkgs.jq
        pkgs.python3
      ];
      systemd.services.thinkterm = {
        wantedBy = [ "multi-user.target" ];
        environment = {
          HOME = "/home/alice";
          XDG_RUNTIME_DIR = "/run/thinkterm-test";
          TS_TLS_EXTRA_CA_FILE = "/run/fixture-ca.pem";
        };
        serviceConfig = {
          User = "alice";
          RuntimeDirectory = "thinkterm-test";
          ExecStart = "${package}/bin/thinkterm-mux-server --skip-config --no-initial-pane";
        };
      };
    };
  };
  testScript = builtins.readFile ./tailnet-smoke.py;
}
