"""Servidor web interativo para geração e gestão de certificados digitais
simulados (ICP-Brasil). Uso exclusivamente educacional."""

import hashlib
import hmac
import io
import json
import os
import secrets
import urllib.request
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

DB_URL = os.environ.get("DB_URL", "postgresql+psycopg2://cert:cert@db:5432/certdb")

engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True)
    username = Column(String(60), unique=True, nullable=False, index=True)
    password_hash = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Certificado(Base):
    __tablename__ = "certificados"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    common_name = Column(String(200), nullable=False)
    organization = Column(String(200), nullable=False)
    country = Column(String(4), nullable=False)
    state = Column(String(200), nullable=False)
    locality = Column(String(200), nullable=False)
    key_size = Column(Integer, nullable=False)
    serial_number = Column(String(80), nullable=False)
    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)
    signature_algorithm = Column(String(40), nullable=False)
    certificate_pem = Column(Text, nullable=False)
    # chave privada NUNCA é persistida — entregue uma única vez na emissão


# ---------- senhas (PBKDF2-HMAC-SHA256, 200k iterações) ----------

def hash_senha(senha: str) -> str:
    salt = secrets.token_bytes(16)
    derivada = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 200_000)
    return f"pbkdf2$200000${salt.hex()}${derivada.hex()}"


def verificar_senha(senha: str, hash_armazenado: str) -> bool:
    try:
        algo, iters, salt_hex, der_hex = hash_armazenado.split("$")
        if algo != "pbkdf2":
            return False
        derivada = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(derivada.hex(), der_hex)
    except Exception:
        return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- criptografia ----------

def gerar_chave(tamanho: int) -> rsa.RSAPrivateKey:
    if tamanho < 2048:
        raise ValueError("Tamanho mínimo da chave é 2048 bits.")
    return rsa.generate_private_key(public_exponent=65537, key_size=tamanho)


def construir_certificado(chave, country, state, locality, organization, common_name):
    nome = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    agora = datetime.now(timezone.utc)
    cert = (
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
    return cert


def detectar_localizacao(ip_cliente: str | None = None) -> dict:
    alvo = ip_cliente or ""
    url = f"http://ip-api.com/json/{alvo}?fields=status,country,countryCode,regionName,city,query"
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:
            dados = json.loads(resp.read().decode("utf-8"))
        if dados.get("status") != "success":
            return {}
        return {
            "ip": dados.get("query", ""),
            "pais": dados.get("countryCode", "BR"),
            "estado": dados.get("regionName", ""),
            "cidade": dados.get("city", ""),
        }
    except Exception:
        return {}


# ---------- schemas ----------

class CertificadoRequest(BaseModel):
    common_name: str = Field(default="Usuário de Teste", max_length=200)
    organization: str = Field(default="Organização Simulada", max_length=200)
    country: str = Field(default="BR", min_length=2, max_length=2)
    state: str = Field(default="São Paulo", max_length=200)
    locality: str = Field(default="São Paulo", max_length=200)
    key_size: int = Field(default=2048, ge=2048, le=8192)


# ---------- app ----------

SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)

app = FastAPI(title="ICP-Brasil Cert Forge", version="1.0.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False,
    max_age=60 * 60 * 8,
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def usuario_atual(request: Request, db: Session) -> Usuario | None:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return db.get(Usuario, uid)


def exigir_usuario(request: Request, db: Session = Depends(get_db)) -> Usuario:
    u = usuario_atual(request, db)
    if not u:
        raise HTTPException(401, "autenticação requerida")
    return u


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


class AuthRequest(BaseModel):
    username: str = Field(min_length=3, max_length=60)
    password: str = Field(min_length=6, max_length=200)


@app.post("/api/auth/register")
def registrar(req: AuthRequest, request: Request, db: Session = Depends(get_db)):
    if db.query(Usuario).filter_by(username=req.username).first():
        raise HTTPException(409, "usuário já existe")
    u = Usuario(username=req.username, password_hash=hash_senha(req.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    request.session["user_id"] = u.id
    return {"id": u.id, "username": u.username}


@app.post("/api/auth/login")
def login(req: AuthRequest, request: Request, db: Session = Depends(get_db)):
    u = db.query(Usuario).filter_by(username=req.username).first()
    if not u or not verificar_senha(req.password, u.password_hash):
        raise HTTPException(401, "credenciais inválidas")
    request.session["user_id"] = u.id
    return {"id": u.id, "username": u.username}


@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request, db: Session = Depends(get_db)):
    u = usuario_atual(request, db)
    if not u:
        return {"autenticado": False}
    return {"autenticado": True, "id": u.id, "username": u.username}


@app.get("/api/geoip")
def geoip(request: Request):
    real_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
    real_ip = real_ip.split(",")[0].strip() if real_ip else ""
    # Se IP for privado/loopback, deixa API detectar pelo IP público do servidor.
    if real_ip.startswith(("10.", "172.", "192.168.", "127.")) or not real_ip:
        real_ip = ""
    geo = detectar_localizacao(real_ip)
    return geo or {"erro": "não foi possível detectar"}


@app.get("/api/stats")
def stats(u: Usuario = Depends(exigir_usuario), db: Session = Depends(get_db)):
    q = db.query(Certificado).filter_by(owner_id=u.id)
    total = q.count()
    por_tamanho = {}
    for c in q.all():
        por_tamanho[str(c.key_size)] = por_tamanho.get(str(c.key_size), 0) + 1
    return {"total": total, "por_tamanho": por_tamanho}


@app.get("/api/certificados")
def listar(u: Usuario = Depends(exigir_usuario), db: Session = Depends(get_db)):
    itens = db.query(Certificado).filter_by(owner_id=u.id).order_by(Certificado.id.desc()).all()
    return [
        {
            "id": c.id,
            "created_at": c.created_at.isoformat(),
            "common_name": c.common_name,
            "organization": c.organization,
            "country": c.country,
            "state": c.state,
            "locality": c.locality,
            "key_size": c.key_size,
            "serial_number": c.serial_number,
            "not_before": c.not_before.isoformat(),
            "not_after": c.not_after.isoformat(),
            "signature_algorithm": c.signature_algorithm,
        }
        for c in itens
    ]


@app.get("/api/certificados/{cert_id}")
def detalhar(cert_id: int, u: Usuario = Depends(exigir_usuario), db: Session = Depends(get_db)):
    c = db.get(Certificado, cert_id)
    if not c or c.owner_id != u.id:
        raise HTTPException(404, "Certificado não encontrado")
    return {
        "id": c.id,
        "created_at": c.created_at.isoformat(),
        "common_name": c.common_name,
        "organization": c.organization,
        "country": c.country,
        "state": c.state,
        "locality": c.locality,
        "key_size": c.key_size,
        "serial_number": c.serial_number,
        "not_before": c.not_before.isoformat(),
        "not_after": c.not_after.isoformat(),
        "signature_algorithm": c.signature_algorithm,
        "certificate_pem": c.certificate_pem,
    }


@app.post("/api/certificados")
def criar(req: CertificadoRequest, u: Usuario = Depends(exigir_usuario), db: Session = Depends(get_db)):
    try:
        chave = gerar_chave(req.key_size)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cert = construir_certificado(chave, req.country, req.state, req.locality, req.organization, req.common_name)

    priv_pem = chave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    registro = Certificado(
        owner_id=u.id,
        common_name=req.common_name,
        organization=req.organization,
        country=req.country,
        state=req.state,
        locality=req.locality,
        key_size=req.key_size,
        serial_number=f"{cert.serial_number:x}",
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        signature_algorithm=cert.signature_hash_algorithm.name.upper(),
        certificate_pem=cert_pem,
    )
    db.add(registro)
    db.commit()
    db.refresh(registro)
    # chave privada devolvida apenas aqui — não persistida
    return {
        "id": registro.id,
        "serial_number": registro.serial_number,
        "private_key_pem": priv_pem,
        "aviso": "Guarde esta chave privada agora. O servidor NÃO armazena cópia e não é possível recuperá-la.",
    }


@app.get("/api/certificados/{cert_id}/download/{tipo}")
def baixar(cert_id: int, tipo: str, u: Usuario = Depends(exigir_usuario), db: Session = Depends(get_db)):
    c = db.get(Certificado, cert_id)
    if not c or c.owner_id != u.id:
        raise HTTPException(404, "Certificado não encontrado")
    if tipo == "certificate":
        conteudo, nome = c.certificate_pem, f"certificate_{cert_id}.pem"
    elif tipo == "private":
        raise HTTPException(410, "Chave privada não é armazenada pelo servidor — a AC não guarda cópia. Deveria ter sido salva no momento da emissão.")
    else:
        raise HTTPException(400, "Tipo inválido. Use 'certificate'.")
    return StreamingResponse(
        io.BytesIO(conteudo.encode()),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{nome}"'},
    )


@app.delete("/api/certificados/{cert_id}")
def deletar(cert_id: int, u: Usuario = Depends(exigir_usuario), db: Session = Depends(get_db)):
    c = db.get(Certificado, cert_id)
    if not c or c.owner_id != u.id:
        raise HTTPException(404, "Certificado não encontrado")
    db.delete(c)
    db.commit()
    return JSONResponse({"ok": True})
