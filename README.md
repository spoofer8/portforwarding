# portforwarding

A small web UI for forwarding ports from a public VPS to machines on your Tailscale network,
for hosting things from behind CGNAT. Pick an IP, a port and TCP, UDP or both. The app adds
the iptables DNAT/SNAT rules and re-applies them every time it starts, so they survive reboots.

How a forward works: traffic hitting `<public IP>:<port>` on the VPS is DNATed to
`<target IP>:<port>` and SNATed to the VPS's Tailscale IP, so replies route back through the tunnel.

## Requirements

- A Linux VPS with `iptables`, IP forwarding on (`sysctl net.ipv4.ip_forward=1`) and Tailscale.
- The targets must be reachable from the VPS over Tailscale: either Tailscale IPs, or LAN IPs
  behind a subnet router.
- Python 3.10+.

## Install

```bash
git clone https://github.com/spoofer8/portforwarding.git /root/portforwarding
cd /root/portforwarding
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Set PF_BIND_IP (tailscale ip -4) and PF_PUBLIC_IP in the unit file, then:
cp portforwarding.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now portforwarding
```

Open `http://<PF_BIND_IP>:3009` from a device on your tailnet.

## Settings

Environment variables, set in `portforwarding.service`:

| Variable | Required | Meaning |
|---|---|---|
| `PF_BIND_IP` | yes | This VPS's Tailscale IPv4. The UI only listens here, and forwarded traffic is SNATed to it. |
| `PF_PUBLIC_IP` | no | Shown on the page as the address the ports are reachable on. |
| `PF_PORT` | no | UI port, default `3009`. |
| `PF_DEBUG` | no | `1` turns on Flask debug mode. Leave it off. |

## Notes

- Rules are saved to `rules.json` next to the script. On first start the app adopts any matching
  forwards already in iptables.
- The UI has no login. Anyone who can reach `PF_BIND_IP:3009` on your tailnet can add forwards,
  so restrict it with Tailscale ACLs if others share your tailnet.
- Remember to allow the forwarded ports in your VPS provider's firewall too.
