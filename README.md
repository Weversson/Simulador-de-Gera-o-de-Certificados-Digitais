# CERTFORGE · ICP-Brasil Simulado

Servidor web interativo (FastAPI + PostgreSQL) com frontend futurista
(glassmorphism + neon) para gerar, armazenar e gerenciar certificados
digitais X.509 autoassinados em conformidade didática com a ICP-Brasil.

> **Uso exclusivamente educacional.** Não utilize em produção.

## Stack

- **Frontend:** HTML5 + CSS moderno (glassmorphism, neon grid, animações) + Vanilla JS
- **Backend:** FastAPI + Uvicorn (Python 3.12)
- **Banco de dados:** PostgreSQL 16 (Alpine Linux)
- **Contêineres:** Debian 12 (bookworm-slim) para web, Alpine para DB
- **Criptografia:** biblioteca `cryptography` (PyCA) — RSA + X.509

## Como executar

```bash
docker compose up --build
```

Abra `http://localhost:8000`.

## Funcionalidades do sistema

- **Forjar novo certificado** (formulário): CN, O, C, ST, L, tamanho da chave (2048–8192).
- **Detectar localização via IP** (botão no formulário).
- **Telemetria** em tempo real: total emitido e distribuição por tamanho.
- **Vault**: lista todos os certificados com ações por linha:
  - `⌕` ver detalhes (modal com campos + PEM)
  - `⇣C` baixar certificate.pem
  - `⇣K` baixar private_key.pem
  - `×` revogar (delete)

## Endpoints HTTP

| Método | Rota | Descrição |
|---|---|---|
| GET | `/` | Interface web |
| GET | `/api/geoip` | Detecta localização do cliente |
| GET | `/api/stats` | Estatísticas |
| GET | `/api/certificados` | Lista todos |
| POST | `/api/certificados` | Gera + armazena |
| GET | `/api/certificados/{id}` | Detalhes + PEM |
| GET | `/api/certificados/{id}/download/{certificate\|private}` | Download |
| DELETE | `/api/certificados/{id}` | Remove |

## Modo CLI (script original)

Ainda disponível:

```bash
docker compose run --rm cli
# ou com parâmetros:
docker compose run --rm cli --tamanho 4096 --saida /out
```

## Schema do banco

Tabela `certificados`:
- `id`, `created_at`, `common_name`, `organization`, `country`, `state`, `locality`
- `key_size`, `serial_number`, `not_before`, `not_after`, `signature_algorithm`
- `private_key_pem`, `certificate_pem`

## Validação

```bash
# subir stack
docker compose up -d --build

# criar certificado via API
curl -X POST http://localhost:8000/api/certificados \
     -H "content-type: application/json" \
     -d '{"common_name":"Teste","organization":"Org","country":"BR","state":"SP","locality":"São Paulo","key_size":2048}'

# listar
curl http://localhost:8000/api/certificados
```
