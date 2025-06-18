import argparse
import subprocess
import sys
import shutil
import os
import ipaddress
from ipwhois import IPWhois
import requests


def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def whois_lookup(ip):
    """Return RDAP/WHOIS information for *ip* using ipwhois."""
    obj = IPWhois(ip)
    try:
        res = obj.lookup_rdap(depth=1)
    except Exception as e:
        return {'error': str(e)}
    return res


def geolocation_lookup(ip, token=None):
    """Return geolocation data from ipinfo.io for *ip*."""
    params = {}
    if token:
        params['token'] = token
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json", params=params, timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def traceroute(ip, hops=10):
    """Run traceroute/tracert for *ip* and return its output."""
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


def process_ip(ip, hops, token=None):
    """Lookup and display information for a single IP address."""
    if not is_valid_ip(ip):
        print(f"{ip} é inválido.")
        return

    print('===== WHOIS / ASN =====')
    whois_info = whois_lookup(ip)
    print(whois_info)

    print('\n===== GEOLOCATION =====')
    geo_info = geolocation_lookup(ip, token=token)
    print(geo_info)

    print('\n===== TRACEROUTE =====')
    trace = traceroute(ip, hops)
    print(trace)


def process_file(path, hops, token=None):
    """Read IPs from *path* and process each one."""
    try:
        with open(path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f'Erro ao ler arquivo: {e}')
        return

    for ip in ips:
        if not is_valid_ip(ip):
            print(f"{ip} é inválido. Pulando...")
            continue
        print(f"\n===== CONSULTANDO {ip} =====")
        process_ip(ip, hops, token=token)


def menu(hops, token=None):
    """Interactive prompt for querying IPs or files."""
    while True:
        print('\nMenu:')
        print('1) Inserir um endereço IP')
        print('2) Informar arquivo com lista de IPs')
        print('0) Sair')
        choice = input('Opção: ').strip()
        if choice == '1':
            ip = input('Digite o IP: ').strip()
            if ip:
                process_ip(ip, hops, token=token)
        elif choice == '2':
            path = input('Caminho do arquivo: ').strip()
            if path:
                process_file(path, hops, token=token)
        elif choice == '0':
            break
        else:
            print('Opção inválida.')


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description='IP information tool')
    parser.add_argument('ip', nargs='?', help='IP address to query')
    parser.add_argument('--file', help='File with list of IP addresses')
    parser.add_argument('--hops', type=int, default=10, help='Max hops for traceroute')
    parser.add_argument('--token', help='IPinfo API token (or set IPINFO_TOKEN env var)')
    args = parser.parse_args()

    token = args.token or os.getenv('IPINFO_TOKEN')

    if args.ip:
        process_ip(args.ip, args.hops, token=token)
    elif args.file:
        process_file(args.file, args.hops, token=token)
    else:
        menu(args.hops, token=token)


if __name__ == '__main__':
    main()
