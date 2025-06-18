import argparse
import subprocess
import sys
import shutil
from ipwhois import IPWhois
import requests


def whois_lookup(ip):
    obj = IPWhois(ip)
    try:
        res = obj.lookup_rdap(depth=1)
    except Exception as e:
        return {'error': str(e)}
    return res


def geolocation_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def traceroute(ip, hops=10):
    """Run traceroute/tracert if disponível."""
    cmd = 'traceroute'
    args = ['-m', str(hops), ip]
    if sys.platform.startswith('win'):
        cmd = 'tracert'
        args = ['-h', str(hops), ip]

    if shutil.which(cmd) is None:
        return f"{cmd} não encontrado no sistema."

    try:
        output = subprocess.check_output([cmd, *args], stderr=subprocess.STDOUT, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return e.output


def main():
    parser = argparse.ArgumentParser(description='IP information tool')
    parser.add_argument('ip', help='IP address to query')
    parser.add_argument('--hops', type=int, default=10, help='Max hops for traceroute')
    args = parser.parse_args()

    print('===== WHOIS / ASN =====')
    whois_info = whois_lookup(args.ip)
    print(whois_info)

    print('\n===== GEOLOCATION =====')
    geo_info = geolocation_lookup(args.ip)
    print(geo_info)

    print('\n===== TRACEROUTE =====')
    trace = traceroute(args.ip, args.hops)
    print(trace)


if __name__ == '__main__':
    main()
