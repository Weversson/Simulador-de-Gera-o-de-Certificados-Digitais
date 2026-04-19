"""Gera um par de chaves RSA e um certificado X.509 autoassinado simulando
a emissão no padrão ICP-Brasil. Uso exclusivamente educacional."""

import argparse
import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def detectar_localizacao() -> dict:
    """Consulta ip-api.com para obter país, estado e cidade via IP público.
    Retorna dicionário com chaves 'pais', 'estado', 'cidade', 'ip' — ou {} em falha."""
    url = "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,query"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            dados = json.loads(resp.read().decode("utf-8"))
        if dados.get("status") != "success":
            return {}
        return {
            "pais": dados.get("countryCode", "BR"),
            "estado": dados.get("regionName", ""),
            "cidade": dados.get("city", ""),
            "ip": dados.get("query", ""),
        }
    except Exception as e:
        print(f"[aviso] falha ao detectar localização via IP: {e}")
        return {}


def gerar_chave(tamanho: int) -> rsa.RSAPrivateKey:
    if tamanho < 2048:
        raise ValueError("Tamanho mínimo da chave é 2048 bits.")
    return rsa.generate_private_key(public_exponent=65537, key_size=tamanho)


def construir_certificado(
    chave: rsa.RSAPrivateKey,
    estado: str,
    cidade: str,
    organizacao: str,
    nome_comum: str,
) -> x509.Certificate:
    nome = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, estado),
        x509.NameAttribute(NameOID.LOCALITY_NAME, cidade),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizacao),
        x509.NameAttribute(NameOID.COMMON_NAME, nome_comum),
    ])
    agora = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=chave, algorithm=hashes.SHA256())
    )


def salvar(chave: rsa.RSAPrivateKey, cert: x509.Certificate, saida: Path) -> None:
    saida.mkdir(parents=True, exist_ok=True)
    caminho_chave = saida / "private_key.pem"
    caminho_cert = saida / "certificate.pem"

    pem_chave = chave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    caminho_chave.write_bytes(pem_chave)
    try:
        os.chmod(caminho_chave, 0o600)
    except PermissionError:
        pass

    caminho_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Chave privada salva em: {caminho_chave}")
    print(f"Certificado salvo em:   {caminho_cert}")


def exibir_resumo(chave: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
    linha = "=" * 70
    print("\n" + linha)
    print(" CERTIFICADO DIGITAL SIMULADO — ICP-Brasil (uso educacional)")
    print(linha)

    print("\n[ Par de Chaves RSA ]")
    print(f"  Algoritmo............: RSA")
    print(f"  Tamanho da chave.....: {chave.key_size} bits")
    print(f"  Expoente público.....: {chave.public_key().public_numbers().e}")

    print("\n[ Sujeito (Subject) do Certificado ]")
    mapa = {
        NameOID.COUNTRY_NAME: "País.................",
        NameOID.STATE_OR_PROVINCE_NAME: "Estado/Província.....",
        NameOID.LOCALITY_NAME: "Localidade...........",
        NameOID.ORGANIZATION_NAME: "Organização..........",
        NameOID.COMMON_NAME: "Nome comum (CN)......",
    }
    for attr in cert.subject:
        rotulo = mapa.get(attr.oid, attr.oid.dotted_string)
        print(f"  {rotulo}: {attr.value}")

    print("\n[ Validade ]")
    inicio = cert.not_valid_before_utc
    fim = cert.not_valid_after_utc
    print(f"  Início...............: {inicio:%d/%m/%Y %H:%M:%S} UTC")
    print(f"  Término..............: {fim:%d/%m/%Y %H:%M:%S} UTC")
    print(f"  Duração..............: {(fim - inicio).days} dias")

    print("\n[ Metadados ]")
    print(f"  Número de série......: {cert.serial_number:x}")
    print(f"  Algoritmo de assin...: {cert.signature_hash_algorithm.name.upper()}")
    print(f"  Emissor (Issuer).....: autoassinado (mesmo Subject)")
    print(linha + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerador de certificado X.509 simulado (ICP-Brasil).")
    parser.add_argument("--tamanho", type=int, default=2048, help="Tamanho da chave RSA (mín. 2048).")
    parser.add_argument("--estado", default=None, help="Se omitido, detectado via IP.")
    parser.add_argument("--cidade", default=None, help="Se omitido, detectado via IP.")
    parser.add_argument("--organizacao", default="Organização Simulada")
    parser.add_argument("--nome-comum", default="Usuário de Teste")
    parser.add_argument("--saida", default="./saida", help="Diretório de saída dos arquivos PEM.")
    parser.add_argument("--sem-geoip", action="store_true", help="Desabilita detecção por IP.")
    args = parser.parse_args()

    estado = args.estado
    cidade = args.cidade
    if (estado is None or cidade is None) and not args.sem_geoip:
        print("Detectando localização via IP público (ip-api.com)...")
        geo = detectar_localizacao()
        if geo:
            print(f"  IP......: {geo['ip']}")
            print(f"  País....: {geo['pais']}")
            print(f"  Estado..: {geo['estado']}")
            print(f"  Cidade..: {geo['cidade']}")
            estado = estado or geo["estado"]
            cidade = cidade or geo["cidade"]
    estado = estado or "São Paulo"
    cidade = cidade or "São Paulo"

    print(f"Gerando chave RSA de {args.tamanho} bits...")
    chave = gerar_chave(args.tamanho)
    cert = construir_certificado(chave, estado, cidade, args.organizacao, args.nome_comum)
    salvar(chave, cert, Path(args.saida))
    exibir_resumo(chave, cert)
    print("AVISO: uso apenas educacional — não utilize em produção.")


if __name__ == "__main__":
    main()
