# Identificar IP

Ferramenta em Python para consultar informações de um endereço IP. Agora é possível consultar diversas fontes além do WHOIS/ASN e traceroute:

- GeoIP2 (GeoLite2 local)
- Shodan
- AbuseIPDB
- Censys Search
- DNS reverso e listas RBL

## Requisitos

- Python 3.10 ou superior
- Pacotes listados em `requirements.txt`

Para instalar as dependências (versões indicadas em `requirements.txt`):

```bash
pip install -r requirements.txt
```

## Uso

Execute o script `ip_lookup.py` informando o IP desejado ou rode sem argumentos para abrir o menu interativo. Utilize um arquivo `.env` (veja `.env.example`) para definir as chaves de API:

```bash
# executando todas as consultas
python ip_lookup.py 8.8.8.8 --full
# ou simplesmente
python ip_lookup.py
```

Parâmetros adicionais:

- `--hops N` define o número máximo de saltos para o traceroute (padrão 10).
- `--file ARQUIVO` permite informar um arquivo com uma lista de IPs, um por linha.
- `--token TOKEN` ou variável `IPINFO_TOKEN` para autenticar requisições ao IPinfo.
- `--full` executa todas as consultas disponíveis.

Copie o arquivo de exemplo e preencha as credenciais necessárias:

```bash
cp .env.example .env
vi .env
```

O resultado exibirá os dados de WHOIS/ASN, geolocalização e o caminho do traceroute.

## Exemplo de saída

```
===== WHOIS / ASN =====
{'asn': '15169', ... }

===== GEOLOCALIZAÇÃO =====
{'country': 'US', 'region': 'California', ...}

===== TRACEROUTE =====
traceroute to 8.8.8.8 (8.8.8.8), 10 hops max
 1  ...
```

## Licença

Este projeto está disponível sob a licença MIT. Consulte o arquivo `LICENSE` para mais detalhes.
