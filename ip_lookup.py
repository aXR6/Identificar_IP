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


def process_ip(ip, hops):
    print('===== WHOIS / ASN =====')
    whois_info = whois_lookup(ip)
    print(whois_info)

    print('\n===== GEOLOCATION =====')
    geo_info = geolocation_lookup(ip)
    print(geo_info)

    print('\n===== TRACEROUTE =====')
    trace = traceroute(ip, hops)
    print(trace)


def process_file(path, hops):
    try:
        with open(path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f'Erro ao ler arquivo: {e}')
        return

    for ip in ips:
        print(f"\n===== CONSULTANDO {ip} =====")
        process_ip(ip, hops)


def menu(hops):
    while True:
        print('\nMenu:')
        print('1) Inserir um endereço IP')
        print('2) Informar arquivo com lista de IPs')
        print('0) Sair')
        choice = input('Opção: ').strip()
        if choice == '1':
            ip = input('Digite o IP: ').strip()
            if ip:
                process_ip(ip, hops)
        elif choice == '2':
            path = input('Caminho do arquivo: ').strip()
            if path:
                process_file(path, hops)
        elif choice == '0':
            break
        else:
            print('Opção inválida.')


def main():
    parser = argparse.ArgumentParser(description='IP information tool')
    parser.add_argument('ip', nargs='?', help='IP address to query')
    parser.add_argument('--file', help='File with list of IP addresses')
    parser.add_argument('--hops', type=int, default=10, help='Max hops for traceroute')
    args = parser.parse_args()

    if args.ip:
        process_ip(args.ip, args.hops)
    elif args.file:
        process_file(args.file, args.hops)
    else:
        menu(args.hops)


if __name__ == '__main__':
    main()
