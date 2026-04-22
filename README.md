# Documentação Técnica: CertForge

Este documento detalha a arquitetura, o funcionamento interno e os procedimentos operacionais para a geração de certificados digitais X.509 no projeto CertForge. O sistema simula uma Autoridade Certificadora simplificada seguindo os padrões estruturais da ICP-Brasil para fins didáticos.

## 1. Arquitetura do Sistema

O CertForge é estruturado em uma topologia de microserviços contêinerizados:

* **Servidor de Aplicação (Web):** Desenvolvido em Python 3.12 com o framework FastAPI. Gerencia a lógica de negócio, autenticação e interface criptográfica.
* **Banco de Dados (DB):** Instância de PostgreSQL 16 para persistência de metadados e certificados públicos.
* **Interface de Linha de Comando (CLI):** Script independente para geração local de chaves sem necessidade de interface gráfica.
* **Frontend:** Interface baseada em JavaScript assíncrono e CSS estruturado para gerenciamento do "Vault" de certificados.

## 2. Processo Técnico de Geração de Itens Criptográficos

A geração de um certificado no sistema não é apenas uma conversão de dados, mas um procedimento sequencial de quatro estágios baseados na biblioteca Cryptography (PyCA).

### Fase 1: Mapeamento de Identidade (Subject)

O sistema solicita ou detecta dados de identificação do titular. Cada campo é mapeado para um Identificador de Objeto (OID) padrão X.509:

* **Common Name (CN):** O nome do titular ou do domínio.
* **Organization (O):** Nome da entidade.
* **Country (C):** Código de duas letras do país.
* **State (ST) e Locality (L):** Dados geográficos.
* **Automação GeoIP:** O sistema realiza uma requisição HTTP para ip-api.com para extrair localização baseada no endereço IP público do solicitante, preenchendo automaticamente os campos geográficos.

### Fase 2: Geração do Par de Chaves RSA

O núcleo criptográfico utiliza o algoritmo RSA (Rivest-Shamir-Adleman):

* **Geração de Primos:** O sistema gera dois números primos grandes e distintos.
* **Tamanho da Chave:** O usuário define a complexidade (2048, 3072, 4096 ou 8192 bits). Valores abaixo de 2048 são rejeitados para manter conformidade com padrões de segurança modernos.
* **Expoente Público:** Fixado em 65537 (Fermat F4) para otimização de verificação e segurança contra ataques específicos.

### Fase 3: Construção da Estrutura X.509

Com o par de chaves e os dados de identidade, o certificado é montado em memória:

* **Atribuição de Serial:** Um número inteiro aleatório de 64 bits é gerado para identificar o certificado de forma única.
* **Período de Validade:** Define-se o início (not_before) como o instante atual e o término (not_after) para 365 dias no futuro.
* **Extensões de Uso:** O certificado recebe a extensão BasicConstraints com o sinalizador ca=False, indicando que ele é um certificado de entidade final.
* **Assinatura Digital:** O conjunto de dados é processado pelo algoritmo de hash SHA-256 e assinado pela chave privada gerada na Fase 2.

### Fase 4: Persistência e Tratamento de Segredos

O sistema aplica uma política de segurança para a chave privada:

* **Efemeridade na Web:** No servidor app.py, a chave privada é codificada no formato PEM (PKCS#8) e enviada uma única vez para o navegador. Ela é descartada da memória do servidor imediatamente após a resposta HTTP e nunca é gravada no banco de dados.
* **Armazenamento Público:** Apenas o certificado (parte pública) é armazenado no banco de dados para consultas e validações posteriores.

## 3. Passo a Passo para Execução

### 3.1. Preparação do Ambiente

A execução exige o Docker e o Docker Compose instalados no sistema operacional host.

1. Clonar ou copiar os arquivos do projeto para um diretório local.
2. Executar o comando de build e inicialização:
```bash
docker compose up -d --build
```
3. Aguardar a mensagem de prontidão do banco de dados (o healthcheck do PostgreSQL garantirá que o servidor web só inicie após o DB estar operacional).

### 3.2. Operação via Interface Web

1. Acessar `http://localhost:8000`.
2. Realizar o registro de uma conta de usuário (as senhas são protegidas por hash PBKDF2).
3. No painel "Forjar Certificado", inserir os dados de identidade.
4. Acionar o botão de geolocalização se desejar preenchimento automático.
5. Clicar em "Forjar Novo Item".
6. **Atenção Crítica:** Copiar e salvar o conteúdo da chave privada exibido no modal. Não haverá segunda oportunidade para recuperar este arquivo através da interface.

### 3.3. Operação via Script CLI

Para gerar certificados diretamente no terminal do host:

1. Utilizar o perfil CLI do Docker Compose:
```bash
docker compose run --rm cli --tamanho 4096 --nome-comum "Exemplo de Nome" --organizacao "Minha Empresa" --saida /out
```
2. Os arquivos `private_key.pem` e `certificate.pem` estarão disponíveis na pasta `./saida` do seu diretório local.

## 4. Endpoints da API para Integração

| Rota | Descrição |
| :--- | :--- |
| `POST /api/certificados` | Envia metadados para geração e retorna o par de chaves em JSON. |
| `GET /api/certificados` | Lista todos os certificados públicos associados ao usuário logado. |
| `GET /api/stats` | Retorna estatísticas globais de emissão e distribuição de tamanhos de chaves. |
| `DELETE /api/certificados/{id}` | Revoga e remove o certificado público do armazenamento. |

## 5. Considerações de Segurança

Este projeto utiliza implementações criptográficas reais, porém, por ser um sistema de certificados autoassinados, não possui raiz de confiança em navegadores comerciais. O uso deve ser restrito a ambientes de teste, desenvolvimento e aprendizado de infraestrutura de chaves públicas (PKI).
