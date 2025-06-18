# Identificar IP

Ferramenta em Python para consultar informações de um endereço IP. O programa realiza consultas WHOIS/ASN, geolocalização e executa um traceroute.

## Requisitos

- Python 3.10 ou superior
- Pacotes listados em `requirements.txt`

Para instalar as dependências:

```bash
pip install -r requirements.txt
```

## Uso

Execute o script `ip_lookup.py` informando o IP desejado ou rode sem argumentos para abrir o menu interativo:

```bash
python ip_lookup.py 8.8.8.8
# ou simplesmente
python ip_lookup.py
```

Parâmetros adicionais:

- `--hops N` define o número máximo de saltos para o traceroute (padrão 10).
- `--file ARQUIVO` permite informar um arquivo com uma lista de IPs, um por linha.

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

Este projeto está disponível sob a licença MIT.
