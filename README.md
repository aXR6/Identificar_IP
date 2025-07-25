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

Após clonar o repositório, instale as dependências (versões indicadas em `requirements.txt`):

```bash
pip install -r requirements.txt
```

## Instalação

Clone o projeto e entre no diretório:

```bash
git clone https://github.com/aXR6/Identificar_IP.git
cd Identificar_IP
```

Após ajustar o arquivo `.env` (copiando o exemplo), carregue as variáveis de
ambiente com o script `init-env.sh`:

```bash
cp .env.example .env
vi .env
source init-env.sh
```

## Uso

Execute o script `ip_lookup.py` com o Python 3 informando o IP desejado ou rode sem argumentos para abrir o menu interativo. Utilize um arquivo `.env` (veja `.env.example`) para definir as chaves de API:

```bash
# executando todas as consultas
python3 ip_lookup.py 8.8.8.8 --full
# incluindo histórico do Shodan
python3 ip_lookup.py 8.8.8.8 --full --history
# ou simplesmente
python3 ip_lookup.py
```

Parâmetros adicionais:

- `--hops N` define o número máximo de saltos para o traceroute (padrão 10).
- `--file ARQUIVO` permite informar um arquivo com uma lista de IPs, um por linha.
- `--token TOKEN` ou variável `IPINFO_TOKEN` para autenticar requisições ao IPinfo.
- `--full` executa todas as consultas disponíveis.
- `--history` inclui banners históricos nas consultas ao Shodan (requer conta com Membership).
- O menu possui uma opção para ler uma lista de IPs de um arquivo. Após todas as
  verificações, é criado automaticamente um arquivo `result_data_hora.txt` na pasta do
  projeto contendo todas as saídas. Ferramentas sem retorno não terão seu bloco
  gravado nesse arquivo.

Copie o arquivo de exemplo e preencha as credenciais necessárias:

```bash
cp .env.example .env
vi .env
```
### Onde obter as chaves de API

Algumas consultas dependem de serviços externos que exigem cadastro. Crie conta
gratuitamente (quando disponível) nos sites abaixo para gerar sua chave:

- [ipinfo.io](https://ipinfo.io/) – token para geolocalização IP.
- [MaxMind](https://www.maxmind.com/) – download do banco GeoLite2 (GeoIP2).
- [Shodan](https://www.shodan.io/) – consultas sobre portas e serviços.
- [AbuseIPDB](https://www.abuseipdb.com/) – reputação e denúncias de IPs.
- [Censys](https://search.censys.io/) – informações de certificados e hosts.

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
