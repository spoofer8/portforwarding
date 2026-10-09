from flask import Flask, request, render_template, redirect, url_for
import ipaddress
import json
import os
import re
import subprocess

app = Flask(__name__)

# The Tailscale (VPN) IP of this machine: the UI only listens here, and forwarded traffic is
# source-NATed to it so replies route back through the tunnel.
VPN_IP = os.environ.get('PF_BIND_IP', '')
# Shown on the page so you know which address the forwarded ports are reachable on.
PUBLIC_IP = os.environ.get('PF_PUBLIC_IP', '')
PORT = int(os.environ.get('PF_PORT', '3009'))

# Rules are saved here and re-applied on every start, so they survive reboots.
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules.json')
PROTOCOLS = ('tcp', 'udp')


def rule_specs(ip, port, proto):
    """The PREROUTING (DNAT) and POSTROUTING (SNAT) rules for one forward."""
    return [
        ['PREROUTING', '-p', proto, '-m', proto, '--dport', port, '-j', 'DNAT', '--to-destination', f'{ip}:{port}'],
        ['POSTROUTING', '-d', f'{ip}/32', '-p', proto, '-m', proto, '--dport', port, '-j', 'SNAT', '--to-source', VPN_IP],
    ]


def iptables(action, spec):
    return subprocess.run(['iptables', '-t', 'nat', action, *spec],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def apply_rule(ip, port, proto):
    """Add both rules unless already present (safe to call repeatedly)."""
    for spec in rule_specs(ip, port, proto):
        if not iptables('-C', spec) and not iptables('-A', spec):
            return False
    return True


def delete_rule(ip, port, proto):
    for spec in rule_specs(ip, port, proto):
        while iptables('-C', spec):
            iptables('-D', spec)


def load_rules():
    try:
        with open(RULES_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_rules(rules):
    tmp = RULES_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(sorted(rules, key=lambda r: (r['ip'], int(r['port']), r['proto'])), f, indent=2)
    os.replace(tmp, RULES_FILE)


def import_live_rules():
    """First run: adopt forwards that already exist in iptables (DNAT ip:port + matching SNAT)."""
    out = subprocess.run(['iptables', '-t', 'nat', '-S'], stdout=subprocess.PIPE, text=True).stdout
    rules = []
    for m in re.finditer(r'-A PREROUTING -p (tcp|udp) -m \1 --dport (\d+) -j DNAT --to-destination ([\d.]+):\2$', out, re.M):
        proto, port, ip = m.groups()
        if f'-A POSTROUTING -d {ip}/32 -p {proto} -m {proto} --dport {port} -j SNAT --to-source {VPN_IP}' in out:
            rules.append({'ip': ip, 'port': port, 'proto': proto})
    return rules


def restore_rules():
    rules = load_rules()
    if rules is None:
        rules = import_live_rules()
        save_rules(rules)
    for r in rules:
        if not apply_rule(r['ip'], r['port'], r['proto']):
            print(f"Error restoring {r['proto']} {r['ip']}:{r['port']}", flush=True)
    print(f"Restored {len(rules)} forwarding rule(s) from {RULES_FILE}", flush=True)


def get_port_forwarding_rules():
    """Retrieve the PREROUTING section of the current port forwarding rules."""
    try:
        result = subprocess.run(['iptables', '-t', 'nat', '-L', 'PREROUTING', '-n', '-v'],
                                stdout=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving rules: {e}")
        return ""


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ip = (request.form.get('ip') or '').strip()
        port = (request.form.get('port') or '').strip()
        proto = request.form.get('proto', 'tcp')
        action = request.form.get('action')

        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return "Invalid IP address.", 400
        if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            return "Invalid port.", 400
        protos = PROTOCOLS if proto == 'both' else (proto,)
        if any(p not in PROTOCOLS for p in protos):
            return "Invalid protocol.", 400

        rules = load_rules() or []
        if action == 'add':
            for p in protos:
                if not apply_rule(ip, port, p):
                    return f"Failed to add {p} port forwarding rule.", 500
                entry = {'ip': ip, 'port': port, 'proto': p}
                if entry not in rules:
                    rules.append(entry)
        elif action == 'remove':
            for p in protos:
                delete_rule(ip, port, p)
            rules = [r for r in rules if not (r['ip'] == ip and r['port'] == port and r['proto'] in protos)]
        else:
            return "Invalid action.", 400
        save_rules(rules)
        return redirect(url_for('index'))

    return render_template('index.html', rules=get_port_forwarding_rules(), saved=load_rules() or [], public_ip=PUBLIC_IP)


if __name__ == '__main__':
    try:
        ipaddress.IPv4Address(VPN_IP)
    except ValueError:
        raise SystemExit('Set PF_BIND_IP to this machine\'s Tailscale IPv4 address (e.g. in portforwarding.service).')
    restore_rules()
    app.run(host=VPN_IP, port=PORT, debug=os.environ.get('PF_DEBUG') == '1')
