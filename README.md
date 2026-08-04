# Fila de Carregamento — Railway + PostgreSQL

Sistema compartilhado para o motorista marcar a chegada pelo próprio celular usando QR Code, código do dia e geolocalização.

## Estrutura

- `server.js`: API, regras, autenticação e criação automática das tabelas.
- `public/index.html`: tela do motorista e painel administrativo.
- `package.json`: dependências e comando de inicialização.
- `.env.example`: variáveis necessárias.

## Publicação no Railway

1. Crie um repositório no GitHub e envie todos os arquivos mantendo a pasta `public`.
2. No Railway, crie um projeto usando **Deploy from GitHub repo**.
3. Dentro do mesmo projeto, clique em **New > Database > PostgreSQL**.
4. No serviço do sistema, configure estas variáveis:

```env
DATABASE_URL=${{Postgres.DATABASE_URL}}
ADMIN_PASSWORD=coloque-uma-senha-forte
TOKEN_SECRET=coloque-um-segredo-com-pelo-menos-24-caracteres
UNIT_NAME=Unidade de Carregamento
DAILY_CODE=4827
UNIT_LAT=0
UNIT_LON=0
RADIUS_METERS=200
BLOCK_DEVICE=true
NODE_ENV=production
```

5. Gere um domínio público para o serviço.
6. Abra o endereço, entre no painel e configure as coordenadas reais da unidade.
7. Gere e imprima o QR Code pelo próprio painel.

## Primeiro acesso

A senha do painel é o valor definido em `ADMIN_PASSWORD`.

## Importante

Não coloque a senha administrativa nem a URL do banco dentro do arquivo `public/index.html`. Essas informações ficam apenas nas variáveis do Railway.
