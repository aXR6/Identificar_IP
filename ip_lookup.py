import argparse
import subprocess
import sys
import shutil
import os
import ipaddress
from ipwhois import IPWhois
import requests
from typing import Any, Dict, List

from dotenv import load_dotenv
import dns.resolver
import geoip2.database
from shodan import Shodan
from censys.search import CensysHosts


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


def geoip2_lookup(ip, db_path=None):
    """Return geolocation data using a local GeoIP2 database."""
    db_path = db_path or os.getenv('GEOIP2_DB')
    if not db_path:
        return {'error': 'GEOIP2_DB não configurado'}
    try:
        reader = geoip2.database.Reader(db_path)
        response = reader.city(ip)
        reader.close()
        return {
            'city': response.city.name,
            'region': response.subdivisions.most_specific.name,
            'country': response.country.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'timezone': response.location.time_zone,
        }
    except Exception as e:
        return {'error': str(e)}


def shodan_lookup(ip, api_key=None):
    """Return Shodan data for *ip*."""
    api_key = api_key or os.getenv('SHODAN_API_KEY')
    if not api_key:
        print('Chave da API do Shodan não configurada (SHODAN_API_KEY).')
        print('Consulte o README para obter e definir a chave.')
        return {}
    try:
        api = Shodan(api_key)
        return api.host(ip)
    except Exception as e:
        return {'error': str(e)}


def abuseipdb_lookup(ip, api_key=None):
    """Query AbuseIPDB for *ip*."""
    api_key = api_key or os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        print('Chave da API do AbuseIPDB não configurada (ABUSEIPDB_API_KEY).')
        print('Cadastre-se no site e defina a chave para usar esta consulta.')
        return {}
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': api_key, 'Accept': 'application/json'}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=10)
        if res.status_code == 200:
            return res.json()
        else:
            return {'error': f'HTTP {res.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def censys_lookup(ip, api_id=None, api_secret=None):
    """Return Censys information for *ip*."""
    api_id = api_id or os.getenv('CENSYS_API_ID')
    api_secret = api_secret or os.getenv('CENSYS_API_SECRET')
    if not api_id or not api_secret:
        print('Credenciais do Censys não configuradas (CENSYS_API_ID/SECRET).')
        print('Cadastre-se no Censys para obter as credenciais necessárias.')
        return {}
    try:
        client = CensysHosts(api_id=api_id, api_secret=api_secret)
        return client.view(ip)
    except Exception as e:
        return {'error': str(e)}


def dns_lookup(ip):
    """Return PTR records for *ip*."""
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, 'PTR')
        return {'ptr': [str(r) for r in answers]}
    except Exception as e:
        return {'error': str(e)}


def rbl_check(ip, rbls=None):
    """Check if *ip* is listed on common RBLs."""
    if rbls is None:
        rbls = ['zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net']
    reversed_ip = '.'.join(reversed(ip.split('.')))
    result = {}
    for rbl in rbls:
        query = f'{reversed_ip}.{rbl}'
        try:
            dns.resolver.resolve(query, 'A')
            result[rbl] = True
        except dns.resolver.NXDOMAIN:
            result[rbl] = False
        except Exception as e:
            result[rbl] = str(e)
    return result


def format_whois(info: Dict[str, Any]) -> str:
    """Return a human friendly summary for WHOIS/RDAP data."""
    if not info:
        return ""
    if 'error' in info:
        return f"Erro: {info['error']}"

    lines: List[str] = []
    asn = info.get('asn')
    desc = info.get('asn_description')
    if asn or desc:
        if desc:
            lines.append(f"ASN: {asn} ({desc})")
        else:
            lines.append(f"ASN: {asn}")

    reg = info.get('asn_registry')
    cc = info.get('asn_country_code')
    cidr = info.get('asn_cidr')
    date = info.get('asn_date')
    reg_parts = []
    if reg:
        reg_parts.append(f"Registry: {reg}")
    if cc:
        reg_parts.append(f"Country: {cc}")
    if cidr:
        reg_parts.append(f"CIDR: {cidr}")
    if date:
        reg_parts.append(f"Date: {date}")
    if reg_parts:
        lines.append(" | ".join(reg_parts))

    net = info.get('network') or {}
    if net:
        lines.append('Network:')
        details = []
        if net.get('name'):
            details.append(f"Name: {net.get('name')}")
        if net.get('country'):
            details.append(f"Country: {net.get('country')}")
        if net.get('type'):
            details.append(f"Type: {net.get('type')}")
        if details:
            lines.append('  ' + ' | '.join(details))

        range_str = ''
        if net.get('start_address') or net.get('end_address'):
            range_str = f"{net.get('start_address')} - {net.get('end_address')}"
        cidr = net.get('cidr')
        range_parts = []
        if range_str:
            range_parts.append(f"Range: {range_str}")
        if cidr:
            range_parts.append(f"CIDR: {cidr}")
        if range_parts:
            lines.append('  ' + ' | '.join(range_parts))

    entities = info.get('entities')
    if entities:
        lines.append('Entities: ' + ', '.join(entities))

    return '\n'.join(lines)


def format_geo(info: Dict[str, Any]) -> str:
    """Return a human friendly summary for geolocation data."""
    if not info:
        return ""
    if 'error' in info:
        return f"Erro: {info['error']}"

    key_map = [
        ('ip', 'IP'),
        ('hostname', 'Hostname'),
        ('city', 'City'),
        ('region', 'Region'),
        ('country', 'Country'),
        ('loc', 'Coordinates'),
        ('org', 'Org'),
        ('postal', 'Postal'),
        ('timezone', 'Timezone'),
    ]

    lines: List[str] = []
    for key, label in key_map:
        val = info.get(key)
        if val:
            lines.append(f"{label}: {val}")

    return '\n'.join(lines)


def format_geoip2(info: Dict[str, Any]) -> str:
    """Return a summary for GeoIP2 results."""
    if not info:
        return ""
    if 'error' in info:
        return f"Erro: {info['error']}"
    key_map = [
        ('city', 'City'),
        ('region', 'Region'),
        ('country', 'Country'),
        ('latitude', 'Latitude'),
        ('longitude', 'Longitude'),
        ('timezone', 'Timezone'),
    ]
    lines: List[str] = []
    for key, label in key_map:
        val = info.get(key)
        if val is not None:
            lines.append(f"{label}: {val}")
    return '\n'.join(lines)


def format_dict(info: Dict[str, Any]) -> str:
    """Return indented JSON for *info* or error string."""
    if not info:
        return ""
    if 'error' in info and len(info) == 1:
        return f"Erro: {info['error']}"
    try:
        import json
        return json.dumps(info, indent=2, ensure_ascii=False)
    except Exception:
        return str(info)


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
    print(format_whois(whois_info))

    print('\n===== GEOLOCATION =====')
    geo_info = geolocation_lookup(ip, token=token)
    print(format_geo(geo_info))

    print('\n===== TRACEROUTE =====')
    trace = traceroute(ip, hops)
    print(trace)


def process_all(ip, hops, token=None, db_path=None):
    """Run all available lookups for *ip*."""
    if not is_valid_ip(ip):
        print(f"{ip} é inválido.")
        return

    print('===== WHOIS / ASN =====')
    print(format_whois(whois_lookup(ip)))

    print('\n===== IPINFO GEO =====')
    print(format_geo(geolocation_lookup(ip, token=token)))

    print('\n===== GEOIP2 =====')
    print(format_geoip2(geoip2_lookup(ip, db_path=db_path)))

    print('\n===== SHODAN =====')
    print(format_dict(shodan_lookup(ip)))

    print('\n===== ABUSEIPDB =====')
    print(format_dict(abuseipdb_lookup(ip)))

    print('\n===== CENSYS =====')
    print(format_dict(censys_lookup(ip)))

    print('\n===== DNS =====')
    print(format_dict(dns_lookup(ip)))

    print('\n===== RBL CHECK =====')
    print(format_dict(rbl_check(ip)))

    print('\n===== TRACEROUTE =====')
    print(traceroute(ip, hops))


def process_file(path, hops, token=None, full=False, db_path=None):
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
        if full:
            process_all(ip, hops, token=token, db_path=db_path)
        else:
            process_ip(ip, hops, token=token)


def menu(hops, token=None):
    """Interactive prompt for querying IPs with various tools."""
    load_dotenv()
    db_path = os.getenv('GEOIP2_DB')
    while True:
        print('\nMenu:')
        print('1) WHOIS/ASN')
        print('2) Geolocalização (ipinfo)')
        print('3) GeoIP2')
        print('4) Shodan')
        print('5) AbuseIPDB')
        print('6) Censys')
        print('7) DNS lookup')
        print('8) Verificar RBLs')
        print('9) Traceroute')
        print('10) Todas as ferramentas')
        print('11) Informar arquivo com lista de IPs (todas)')
        print('0) Sair')
        choice = input('Opção: ').strip()
        if choice in {'1','2','3','4','5','6','7','8','9','10'}:
            ip = input('Digite o IP: ').strip()
            if not ip:
                continue
            if choice == '1':
                print(format_whois(whois_lookup(ip)))
            elif choice == '2':
                print(format_geo(geolocation_lookup(ip, token=token)))
            elif choice == '3':
                print(format_geoip2(geoip2_lookup(ip, db_path=db_path)))
            elif choice == '4':
                print(format_dict(shodan_lookup(ip)))
            elif choice == '5':
                print(format_dict(abuseipdb_lookup(ip)))
            elif choice == '6':
                print(format_dict(censys_lookup(ip)))
            elif choice == '7':
                print(format_dict(dns_lookup(ip)))
            elif choice == '8':
                print(format_dict(rbl_check(ip)))
            elif choice == '9':
                print(traceroute(ip, hops))
            elif choice == '10':
                process_all(ip, hops, token=token, db_path=db_path)
        elif choice == '11':
            path = input('Caminho do arquivo: ').strip()
            if path:
                process_file(path, hops, token=token, full=True, db_path=db_path)
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
    parser.add_argument('--full', action='store_true', help='Run all available lookups')
    args = parser.parse_args()

    load_dotenv()
    token = args.token or os.getenv('IPINFO_TOKEN')

    if args.ip:
        if args.full:
            process_all(args.ip, args.hops, token=token)
        else:
            process_ip(args.ip, args.hops, token=token)
    elif args.file:
        process_file(args.file, args.hops, token=token, full=args.full)
    else:
        menu(args.hops, token=token)


if __name__ == '__main__':
    main()
