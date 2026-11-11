import os
import json
import threading
import shutil
import sys
import uuid
import datetime
import urllib.parse
import urllib.request
import urllib.error
import socket
import subprocess
import re
import secrets
import hmac
import hashlib
import qrcode
import ssl
from datetime import datetime as dt_datetime, timedelta, timezone
from PIL import Image, ImageTk, ImageSequence
from tkinter import filedialog, Canvas
import time
from flask import Flask, request, render_template, send_from_directory, jsonify, make_response
from werkzeug.utils import secure_filename
import customtkinter as ctk

# =====================================================
# CONFIGURAÇÕES DO FLASK E UPLOAD
# =====================================================

PUBLIC_URL = ""
PUBLIC_BASE_URL = ""
PUBLIC_URL_READY = threading.Event()
CLOUDFLARED_PROCESS = None
CLOUDFLARED_LOCK = threading.Lock()
CLOUDFLARE_ERROR = ""
AUTH_FAILURES = {}
AUTH_FAILURES_LOCK = threading.Lock()
AUTH_WINDOW_SECONDS = 60
AUTH_MAX_FAILURES = 10


def cloudflared_path():
    """Localiza o cloudflared de 64 bits embutido ou ao lado do programa."""
    filenames = ["cloudflared-win64.exe", "cloudflared.exe"] if os.name == "nt" else ["cloudflared"]
    root = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    for filename in filenames:
        embedded = os.path.join(root, filename)
        if os.path.exists(embedded):
            return embedded
    for filename in filenames:
        local = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        if os.path.exists(local):
            return local
    return None


def start_cloudflared():
    """Inicia o Quick Tunnel sem console e captura a URL HTTPS pública."""
    global PUBLIC_URL, PUBLIC_BASE_URL, CLOUDFLARED_PROCESS, CLOUDFLARE_ERROR
    binary = cloudflared_path()
    if not binary:
        CLOUDFLARE_ERROR = "cloudflared-win64.exe não foi encontrado"
        print(CLOUDFLARE_ERROR)
        PUBLIC_URL_READY.set()
        return

    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

    try:
        process = subprocess.Popen(
            [binary, "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:5000"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=flags,
            startupinfo=startupinfo,
        )
        with CLOUDFLARED_LOCK:
            CLOUDFLARED_PROCESS = process

        pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com(?:/)?")
        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output_lines.append(line.strip())
            match = pattern.search(line)
            if match:
                base_url = match.group(0).rstrip("/")
                PUBLIC_BASE_URL = base_url
                PUBLIC_URL = f"{base_url}/?access={ACCESS_TOKEN}"
                PUBLIC_URL_READY.set()
                break

        if not PUBLIC_URL_READY.is_set():
            CLOUDFLARE_ERROR = output_lines[-1] if output_lines else "cloudflared encerrou sem gerar uma URL"
            PUBLIC_URL_READY.set()
    except Exception as error:
        CLOUDFLARE_ERROR = f"Erro no Cloudflare Tunnel: {error}"
        print(CLOUDFLARE_ERROR)
        PUBLIC_URL_READY.set()


def stop_cloudflared():
    """Finaliza o túnel sem deixar processo órfão no Windows."""
    global CLOUDFLARED_PROCESS
    with CLOUDFLARED_LOCK:
        process = CLOUDFLARED_PROCESS
        CLOUDFLARED_PROCESS = None
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

def rotate_access_token():
    """Gera um novo token e invalida qualquer QR Code anterior."""
    global ACCESS_TOKEN, ACCESS_TOKEN_EXPIRES_AT, ACCESS_TOKEN_USED, PUBLIC_URL
    ACCESS_TOKEN = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRES_AT = time.time() + 120
    ACCESS_TOKEN_USED = False
    if PUBLIC_BASE_URL:
        PUBLIC_URL = f"{PUBLIC_BASE_URL}/?access={ACCESS_TOKEN}"


def allow_auth_attempt(client_key):
    now = time.time()
    with AUTH_FAILURES_LOCK:
        attempts = [value for value in AUTH_FAILURES.get(client_key, []) if now - value < AUTH_WINDOW_SECONDS]
        AUTH_FAILURES[client_key] = attempts
        return len(attempts) < AUTH_MAX_FAILURES


def register_auth_failure(client_key):
    with AUTH_FAILURES_LOCK:
        AUTH_FAILURES.setdefault(client_key, []).append(time.time())


def csrf_is_valid():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    device_token = request.cookies.get(DEVICE_COOKIE, "")
    session = AUTHORIZED_DEVICES.get(device_token, {})
    expected = session.get("csrf", "")
    cookie_value = request.cookies.get("NEXUS_CSRF", "")
    supplied = request.headers.get("X-Nexus-CSRF", "")
    return bool(expected and cookie_value and supplied and hmac.compare_digest(expected, cookie_value) and hmac.compare_digest(expected, supplied))


# Recursos somente leitura ficam embutidos no onefile do PyInstaller.
# Dados graváveis ficam fora do executável, em uma pasta persistente do Windows.
if getattr(sys, "frozen", False):
    BASE_DIR = sys._MEIPASS
    DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "NexusDrop")
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = BASE_DIR

os.makedirs(DATA_DIR, exist_ok=True)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
app = Flask(__name__, template_folder=TEMPLATES_DIR)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

# Token temporário desta execução. O IP sozinho não dá acesso ao servidor.
ACCESS_TOKEN = secrets.token_urlsafe(32)
ACCESS_TOKEN_EXPIRES_AT = time.time() + 120
ACCESS_TOKEN_USED = False
AUTHORIZED_DEVICES = {}
ACTIVE_DEVICE_TOKEN = None
DEVICE_COOKIE = "nexus_device"
SESSION_TTL = 24 * 60 * 60


def is_authorized_device():
    global LAST_DEVICE_HEARTBEAT
    if not is_mobile_request():
        return False
    device_token = request.cookies.get(DEVICE_COOKIE, "")
    session = AUTHORIZED_DEVICES.get(device_token)
    if not device_token or not session or device_token != ACTIVE_DEVICE_TOKEN:
        return False
    if not hmac.compare_digest(session.get("user_agent", ""), user_agent_fingerprint()):
        return False
    if time.time() - float(session.get("created_at", 0)) > SESSION_TTL:
        AUTHORIZED_DEVICES.pop(device_token, None)
        return False
    # Qualquer requisição válida confirma que o dispositivo ainda alcança o PC.
    LAST_DEVICE_HEARTBEAT = time.time()
    return True


def is_mobile_request():
    """Aceita somente navegadores móveis; computadores continuam bloqueados."""
    user_agent = request.headers.get("User-Agent", "").lower()
    return any(value in user_agent for value in ("iphone", "ipod", "ipad", "android", "mobile"))


def user_agent_fingerprint():
    return hashlib.sha256(request.headers.get("User-Agent", "").encode("utf-8")).hexdigest()


def valid_access_token():
    global ACCESS_TOKEN_USED
    supplied = request.args.get("access", "")
    client_key = request.remote_addr or "unknown"
    if not supplied or not allow_auth_attempt(client_key):
        return False
    valid = not ACCESS_TOKEN_USED and time.time() <= ACCESS_TOKEN_EXPIRES_AT and hmac.compare_digest(supplied, ACCESS_TOKEN)
    if not valid:
        register_auth_failure(client_key)
    return valid


def create_tls_certificate(ip_address):
    """Cria uma CA local e um certificado HTTPS assinado por ela."""
    cert_file = os.path.join(DATA_DIR, "nexusdrop-cert.pem")
    key_file = os.path.join(DATA_DIR, "nexusdrop-key.pem")
    ca_cert_file = os.path.join(DATA_DIR, "nexusdrop-ca.pem")
    ca_key_file = os.path.join(DATA_DIR, "nexusdrop-ca-key.pem")
    exported_ca = os.path.join(os.path.expanduser("~"), "Desktop", "NexusDrop-CA.cer")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import ipaddress

        def write_ca():
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            ca_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexusDrop"),
                x509.NameAttribute(NameOID.COMMON_NAME, "NexusDrop Local Authority"),
            ])
            now = dt_datetime.now(timezone.utc)
            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(ca_subject).issuer_name(ca_subject)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False
                ), critical=True)
                .sign(ca_key, hashes.SHA256())
            )
            with open(ca_key_file, "wb") as file:
                file.write(ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))
            with open(ca_cert_file, "wb") as file:
                file.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            return ca_key, ca_cert

        if os.path.exists(ca_key_file) and os.path.exists(ca_cert_file):
            with open(ca_key_file, "rb") as file:
                ca_key = serialization.load_pem_private_key(file.read(), password=None)
            with open(ca_cert_file, "rb") as file:
                ca_cert = x509.load_pem_x509_certificate(file.read())
        else:
            ca_key, ca_cert = write_ca()

        # O .cer é público e pode ser instalado no dispositivo móvel. Nunca exporte o ca_key_file.
        os.makedirs(os.path.dirname(exported_ca), exist_ok=True)
        with open(exported_ca, "wb") as file:
            file.write(ca_cert.public_bytes(serialization.Encoding.DER))

        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexusDrop Local"),
            x509.NameAttribute(NameOID.COMMON_NAME, ip_address),
        ])
        now = dt_datetime.now(timezone.utc)
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_subject).issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(ip_address)),
                x509.DNSName("localhost")
            ]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        with open(key_file, "wb") as file:
            file.write(server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(cert_file, "wb") as file:
            file.write(server_cert.public_bytes(serialization.Encoding.PEM))
        print(f"Certificado CA para instalar no dispositivo móvel: {exported_ca}")
        return cert_file, key_file
    except ImportError as error:
        raise RuntimeError("Instale a dependência HTTPS com: python -m pip install cryptography") from error
    except Exception as error:
        raise RuntimeError(f"Não foi possível criar os certificados HTTPS: {error}") from error

# ================= CONTROLE REMOTO OPCIONAL =================
# Cole somente a URL do projeto e a chave ANON pública.
# Nunca coloque a chave service_role neste arquivo ou no .exe.
APP_VERSION = "1.0.0"
SUPABASE_URL = os.getenv("NEXUSDROP_SUPABASE_URL", "https://SEU-PROJETO.supabase.co")
SUPABASE_ANON_KEY = os.getenv("NEXUSDROP_SUPABASE_ANON_KEY", "COLE_AQUI_A_CHAVE_ANON_PUBLICA")
OFFLINE_GRACE_DAYS = 30
CONTROL_FILE = os.path.join(os.path.expanduser("~"), "AppData", "Local", "NexusDrop", "control.json")
INSTALLATION_FILE = os.path.join(os.path.expanduser("~"), "AppData", "Local", "NexusDrop", "installation_id.txt")
os.makedirs(os.path.dirname(CONTROL_FILE), exist_ok=True)


def get_installation_id():
    try:
        if os.path.exists(INSTALLATION_FILE):
            value = open(INSTALLATION_FILE, "r", encoding="utf-8").read().strip()
            if value:
                return value
        value = str(uuid.uuid4())
        with open(INSTALLATION_FILE, "w", encoding="utf-8") as file:
            file.write(value)
        return value
    except OSError:
        return "local-installation"


def version_tuple(value):
    try:
        return tuple(int(part) for part in str(value).split(".")[:3])
    except (ValueError, TypeError):
        return (0, 0, 0)


def check_remote_control():
    default = {"active": True, "maintenance": False, "minimum_version": "0.0.0", "message": "", "online": False}
    configured = SUPABASE_URL.startswith("https://") and "SEU-PROJETO" not in SUPABASE_URL and "COLE_AQUI" not in SUPABASE_ANON_KEY
    if not configured:
        return default
    try:
        query = urllib.parse.urlencode({"select": "active,maintenance,minimum_version,message,latest_version", "key": "eq.global"})
        url = SUPABASE_URL.rstrip("/") + "/rest/v1/app_control?" + query
        request = urllib.request.Request(url, headers={"apikey": SUPABASE_ANON_KEY, "Authorization": "Bearer " + SUPABASE_ANON_KEY, "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=6) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not data:
            return default
        result = dict(default)
        result.update(data[0])
        result["online"] = True
        with open(CONTROL_FILE, "w", encoding="utf-8") as file:
            json.dump({"checked_at": time.time(), "control": result}, file, ensure_ascii=False)
        return result
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        try:
            cached = json.load(open(CONTROL_FILE, "r", encoding="utf-8"))
            if time.time() - float(cached.get("checked_at", 0)) <= OFFLINE_GRACE_DAYS * 86400:
                result = dict(default)
                result.update(cached.get("control", {}))
                result["offline_cache"] = True
                return result
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return default


def check_app_access():
    # O modo LAN não consulta Supabase, Cloudflare ou qualquer serviço externo.
    return True, "OK"


LAST_PHONE_SEEN = 0
LAST_DEVICE_HEARTBEAT = 0
LAST_UPLOAD_TIME = 0
LAST_UPLOADED_FILE = ""
TRANSFER_STATE = {"active": False, "percent": 0, "files": 0, "name": "", "speed": "0 MB/s"}
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
SESSION_FILE = os.path.join(DATA_DIR, "session.json")
UPLOAD_FOLDER = os.path.join(os.path.expanduser("~"), "Desktop", "NexusDrop_Recebidos")
OUTBOX_FOLDER = os.path.join(os.path.expanduser("~"), "Desktop", "NexusDrop_Para_Dispositivo")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTBOX_FOLDER, exist_ok=True)


def device_folder_name():
    if not ACTIVE_DEVICE_TOKEN:
        return None
    digest = hashlib.sha256(ACTIVE_DEVICE_TOKEN.encode("utf-8")).hexdigest()[:16]
    return f"dispositivo_{digest}"


def active_device_folder(base_folder):
    folder_name = device_folder_name()
    if not folder_name:
        return base_folder
    folder = os.path.join(base_folder, folder_name)
    os.makedirs(folder, exist_ok=True)
    return folder


app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024 * 1024  # Limite de 10GB



def load_session():
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_session(data):
    with open(SESSION_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_history(records):
    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(records[-500:], file, ensure_ascii=False, indent=2)


def add_history(record):
    records = load_history()
    records.append(record)
    save_history(records)


def access_denied():
    """Resposta única para rotas acessadas sem token ou sessão autorizada."""
    response = make_response(jsonify({
        "ok": False,
        "error": "Acesso não autorizado. Escaneie o QR Code atual do NexusDrop."
    }), 403)
    response.delete_cookie(DEVICE_COOKIE)
    response.delete_cookie("NEXUS_CSRF")
    return response


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(BASE_DIR, "assets"), filename)

@app.route("/pc-files", methods=["GET"])
def pc_files():
    if not is_authorized_device():
        return access_denied()
    files = []
    folder = active_device_folder(OUTBOX_FOLDER)
    try:
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                files.append({
                    "name": name,
                    "size": os.path.getsize(path),
                    "modified": time.strftime("%d/%m/%Y %H:%M", time.localtime(os.path.getmtime(path)))
                })
    except OSError:
        pass
    files.sort(key=lambda item: item["name"].lower())
    return jsonify({"files": files})


@app.route("/download/<path:filename>", methods=["GET"])
def download_pc_file(filename):
    if not is_authorized_device():
        return access_denied()
    folder = os.path.realpath(active_device_folder(OUTBOX_FOLDER))
    safe_name = secure_filename(os.path.basename(filename))
    target = os.path.realpath(os.path.join(folder, safe_name))
    if not safe_name or os.path.commonpath([folder, target]) != folder or not os.path.isfile(target):
        return access_denied()
    return send_from_directory(folder, safe_name, as_attachment=True)


@app.route("/transfer-status", methods=["POST"])
def transfer_status():
    global TRANSFER_STATE
    if not is_authorized_device() or not csrf_is_valid():
        return access_denied()
    data = request.get_json(silent=True) or {}
    TRANSFER_STATE.update({
        "active": bool(data.get("active", True)),
        "percent": max(0, min(100, int(data.get("percent", 0)))),
        "files": int(data.get("files", 0)),
        "name": str(data.get("name", ""))[:180],
        "speed": str(data.get("speed", "0 MB/s"))[:40]
    })
    return "ok", 200


@app.route("/presence", methods=["GET"])
def device_presence():
    """Heartbeat leve; confirma que o navegador ainda alcança este PC."""
    global LAST_DEVICE_HEARTBEAT, LAST_PHONE_SEEN
    if not is_authorized_device():
        return access_denied()
    LAST_DEVICE_HEARTBEAT = time.time()
    LAST_PHONE_SEEN = LAST_DEVICE_HEARTBEAT
    return jsonify({"ok": True, "local": True})

@app.route("/", methods=["GET", "POST"])
def upload_file():
    global LAST_PHONE_SEEN, LAST_DEVICE_HEARTBEAT, LAST_UPLOAD_TIME, LAST_UPLOADED_FILE, ACTIVE_DEVICE_TOKEN, ACCESS_TOKEN_USED
    if not is_mobile_request():
        return access_denied()
    supplied_access = request.args.get("access", "")
    if supplied_access and not hmac.compare_digest(supplied_access, ACCESS_TOKEN):
        return access_denied()
    if request.method == "POST":
        if not is_authorized_device() or not csrf_is_valid():
            return access_denied()
        files = request.files.getlist("file")
        if not files:
            return "Nenhum arquivo recebido", 400
        try:
            saved_names = []
            destination_folder = active_device_folder(UPLOAD_FOLDER)
            for file in files:
                if not file.filename:
                    continue
                filename = secure_filename(file.filename)
                if not filename:
                    filename = "arquivo_recebido"
                name, extension = os.path.splitext(filename)
                destination = os.path.join(destination_folder, filename)
                counter = 1
                while os.path.exists(destination):
                    new_filename = f"{name}_{counter}{extension}"
                    destination = os.path.join(destination_folder, new_filename)
                    counter += 1
                partial_destination = destination + ".part"
                file.save(partial_destination)
                os.replace(partial_destination, destination)
                saved_names.append(os.path.basename(destination))
            LAST_UPLOADED_FILE = ", ".join(saved_names)
            TRANSFER_STATE.update({"active": False, "percent": 100, "files": len(saved_names), "name": LAST_UPLOADED_FILE, "speed": "Concluído"})
            LAST_UPLOAD_TIME = time.time()
            add_history({
                "type": "upload",
                "files": LAST_UPLOADED_FILE,
                "ip": request.remote_addr or "desconhecido",
                "device": request.headers.get("User-Agent", "dispositivo móvel"),
                "time": time.strftime("%d/%m/%Y %H:%M:%S")
            })
            return "Sucesso", 200
        except Exception as error:
            try:
                for partial in os.listdir(destination_folder):
                    if partial.endswith(".part"):
                        os.remove(os.path.join(destination_folder, partial))
            except OSError:
                pass
            print("Erro ao salvar transferência:", type(error).__name__)
            return "Erro ao salvar", 500

    # O IP sozinho não é suficiente: a primeira abertura precisa do token do QR.
    if not is_authorized_device() and not valid_access_token():
        return access_denied()
    device_token = request.cookies.get(DEVICE_COOKIE)
    is_new_device = not device_token or device_token not in AUTHORIZED_DEVICES
    if is_new_device:
        # Apenas um dispositivo móvel fica autorizado por vez nesta estação.
        # Isso evita que dois dispositivos compartilhem a mesma fila.
        AUTHORIZED_DEVICES.clear()
        ACCESS_TOKEN_USED = True
        device_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        AUTHORIZED_DEVICES[device_token] = {
            "ip": request.remote_addr or "desconhecido",
            "created_at": time.time(),
            "user_agent": user_agent_fingerprint(),
            "csrf": csrf_token
        }
        ACTIVE_DEVICE_TOKEN = device_token
    if is_new_device:
        LAST_PHONE_SEEN = time.time()
        LAST_DEVICE_HEARTBEAT = LAST_PHONE_SEEN
        scan_time = time.strftime("%d/%m/%Y %H:%M:%S")
        save_session({
            "connected": True,
            "ip": request.remote_addr or "desconhecido",
            "device": request.headers.get("User-Agent", "dispositivo móvel"),
            "time": scan_time
        })
        add_history({
            "type": "scan",
            "files": "QR Code reconhecido",
            "ip": request.remote_addr or "desconhecido",
            "device": request.headers.get("User-Agent", "dispositivo móvel"),
            "time": scan_time
        })
    if is_new_device:
        # Remove o token da barra de endereço depois do pareamento.
        response = make_response("", 302)
        response.headers["Location"] = "/"
    else:
        response = make_response(render_template("mobile.html"))
    # O modo LAN usa HTTP local; Secure=True impediria o cookie de circular no dispositivo móvel.
    response.set_cookie(DEVICE_COOKIE, device_token, max_age=SESSION_TTL, httponly=True, secure=False, samesite="Strict")
    csrf_token = AUTHORIZED_DEVICES.get(device_token, {}).get("csrf", "")
    response.set_cookie("NEXUS_CSRF", csrf_token, max_age=SESSION_TTL, httponly=False, secure=False, samesite="Strict")
    return response

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Endereço reservado apenas para selecionar a interface local; nenhum
        # pacote de aplicação é enviado e não depende de internet.
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        candidates = socket.gethostbyname_ex(socket.gethostname())[2]
        for ip in candidates:
            if "." in ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def start_windows_mobile_hotspot():
    """Tenta iniciar o Hotspot Móvel já configurado no Windows sem usar internet."""
    if os.name != "nt":
        return False, "O Hotspot Móvel automático está disponível somente no Windows."
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return False, "PowerShell não encontrado."
    script = r'''
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -eq $profile) { throw "Nenhuma interface de rede disponível para o Hotspot Móvel." }
$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$result = $manager.StartTetheringAsync().GetAwaiter().GetResult()
if ($result.Status -ne 0 -and $result.Status.ToString() -notmatch "Success|AlreadyOn") { throw "O Windows recusou a ativação: $($result.Status)" }
Write-Output "OK"
'''
    try:
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, text=True, timeout=25, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode == 0 and "OK" in result.stdout:
            return True, "Hotspot Móvel ativado."
        return False, (result.stderr or result.stdout or "O Windows não ativou o Hotspot Móvel.").strip()[-300:]
    except Exception as error:
        return False, str(error)


def configure_legacy_windows_hotspot(ssid, password):
    """Tenta configurar o modo Hosted Network legado quando o adaptador oferece suporte."""
    if os.name != "nt":
        return False, "Disponível somente no Windows."
    if not re.fullmatch(r"[\x20-\x7E]{1,32}", ssid or "") or not re.fullmatch(r"[\x20-\x7E]{8,63}", password or ""):
        return False, "SSID ou senha incompatível com o Hosted Network."
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        setup = subprocess.run(["netsh", "wlan", "set", "hostednetwork", "mode=allow", f"ssid={ssid}", f"key={password}", "keyUsage=persistent"], capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=15, creationflags=flags)
        start = subprocess.run(["netsh", "wlan", "start", "hostednetwork"], capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=15, creationflags=flags)
        output = (setup.stdout + start.stdout + setup.stderr + start.stderr).lower()
        if start.returncode == 0 and "not support" not in output and "não é possível" not in output and "cannot" not in output:
            return True, "Rede offline criada automaticamente."
        return False, (start.stdout or start.stderr or "O adaptador não oferece Hosted Network.").strip()[-300:]
    except Exception as error:
        return False, str(error)


def stop_windows_mobile_hotspot():
    if os.name != "nt":
        return
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return
    script = r'''
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -ne $profile) {
  $manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
  $manager.StopTetheringAsync().GetAwaiter().GetResult() | Out-Null
}
'''
    try:
        subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass
    # Alguns adaptadores usam o Hosted Network legado, que não é desligado
    # pela API moderna de tethering.
    try:
        subprocess.run(["netsh", "wlan", "stop", "hostednetwork"], capture_output=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def detect_hotspot_ip(fallback):
    """Encontra o IP típico da interface de hotspot do Windows."""
    if os.name == "nt":
        try:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            ips = re.findall(r"(?:IPv4[^:]*:|Endere[cç]o IPv4[^:]*:)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", result.stdout, flags=re.IGNORECASE)
            for ip in ips:
                if ip.startswith(("192.168.", "10.", "172.")) and not ip.endswith(".255"):
                    if ip.startswith("192.168.137.") or ip.endswith(".1"):
                        return ip
            for ip in ips:
                if ip.startswith(("192.168.", "10.", "172.")):
                    return ip
        except Exception:
            pass
    return fallback


def hotspot_has_client(local_ip):
    """Detecta um cliente na mesma sub-rede do hotspot usando apenas ARP local."""
    if not local_ip or local_ip == "127.0.0.1":
        return False
    prefix = ".".join(local_ip.split(".")[:3]) + "."
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=4, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout):
            if candidate.startswith(prefix) and candidate != local_ip and not candidate.endswith(".255"):
                return True
    except Exception:
        pass
    return False


def clear_local_arp_cache():
    """Remove vizinhanças antigas antes de iniciar uma sessão offline."""
    if os.name != "nt":
        return
    try:
        subprocess.run(["arp", "-d", "*"], capture_output=True, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass

class ServerThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
    def run(self):
        try:
            # Servidor acessível somente pela rede local. Não inicia túnel externo.
            app.run(host="0.0.0.0", port=5000, threaded=True, use_reloader=False)
        except Exception as error:
            print(f"Erro ao iniciar o servidor local: {error}")


# =====================================================
# INTERFACE DESKTOP PROFISSIONAL
# =====================================================

class ProfessionalApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")
        self.title("NexusDrop")
        self._window_icon = None
        ico_path = os.path.join(BASE_DIR, "assets", "icone2.ico")
        png_path = os.path.join(BASE_DIR, "assets", "icone2.png")
        try:
            if os.path.exists(ico_path):
                self.iconbitmap(ico_path)
            elif os.path.exists(png_path):
                icon_image = Image.open(png_path).convert("RGBA")
                icon_image.thumbnail((48, 48), Image.Resampling.LANCZOS)
                self._window_icon = ImageTk.PhotoImage(icon_image)
                self.iconphoto(True, self._window_icon)
        except Exception as error:
            print(f"Não foi possível carregar o ícone: {error}")
        self.geometry("1240x780")
        self.minsize(1050, 680)
        self.configure(fg_color="#F5F3FF")
        self.local_ip = get_local_ip()
        global PUBLIC_URL, PUBLIC_BASE_URL
        PUBLIC_BASE_URL = f"http://{self.local_ip}:5000"
        PUBLIC_URL = f"{PUBLIC_BASE_URL}/?access={ACCESS_TOKEN}"
        self.url_text = PUBLIC_URL
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.tunnel_notice_shown = False
        self.colors = {
            "blue": "#6750D6", "blue_dark": "#4E3CAF", "navy": "#20233F",
            "sidebar": "#20233F", "sidebar_hover": "#343866", "text": "#24243A",
            "muted": "#777793", "border": "#E3E1F0", "surface": "#FFFFFF",
            "background": "#F5F3FF", "green": "#1D9B72", "orange": "#D88455",
            "purple": "#C05A9A", "coral": "#E87575"
        }
        self.assets_dir = os.path.join(BASE_DIR, "assets")
        self.asset_images = {}
        self.gif_frames = {}
        self.qr_gif_frames = {}
        self.gif_jobs = {}
        self.last_phone_seen = 0
        self.last_upload_time = 0
        self.network_online = None
        self.last_network_check = 0
        self.animation_step = 0
        self.qr_complete_items = []
        self.received_action_rows = []
        self.offline_hotspot_started = False
        self.offline_stage = "network"
        self.offline_status = "Preparando a rede privada do computador..."
        self.offline_ssid = f"NexusDrop-Offline-{secrets.token_hex(2).upper()}"
        self.offline_password = f"Nexus-{secrets.token_urlsafe(10)}"
        self.offline_started_at = 0
        self.offline_app_started_at = 0
        self.current_page = "overview"
        self.nav_buttons = {}
        # Cada execução começa com um pareamento novo; a sessão anterior não
        # deve impedir a etapa de conexão à rede privada.
        self.session = {}
        save_session({})
        self.build_shell()
        self.render_overview()
        self.update_clock()
        self.poll_server_state()
        self.poll_local_url()
        self.after(350, self.bootstrap_offline_network)
        self.after(1500, self.poll_offline_connection)

    def bootstrap_offline_network(self):
        """Cria a rede privada sem bloquear a interface gráfica."""
        if self.offline_hotspot_started:
            return
        threading.Thread(target=self._offline_network_worker, daemon=True, name="NexusDropOfflineNetwork").start()

    def _offline_network_worker(self):
        clear_local_arp_cache()
        ok, message = configure_legacy_windows_hotspot(self.offline_ssid, self.offline_password)
        if ok:
            self.after(0, lambda: self.offline_network_ready(message))
        else:
            self.after(0, lambda: self.offline_network_failed(message))

    def offline_network_ready(self, message):
        self.offline_hotspot_started = True
        self.offline_started_at = time.time()
        clear_local_arp_cache()
        self.local_ip = detect_hotspot_ip(self.local_ip)
        self.offline_status = f"Rede privada ativa: {self.offline_ssid}"
        self._refresh_local_url()
        if self.current_page in ("overview", "connection"):
            self.render_overview() if self.current_page == "overview" else self.render_connection()

    def offline_network_failed(self, message):
        self.offline_status = "O adaptador não permitiu criar a rede automaticamente. Use o botão de configuração do Windows."
        if self.current_page in ("overview", "connection"):
            self.render_overview() if self.current_page == "overview" else self.render_connection()

    def poll_offline_connection(self):
        global LAST_DEVICE_HEARTBEAT
        app_wait = time.time() - self.offline_app_started_at if self.offline_app_started_at else 0
        if self.offline_stage == "app" and app_wait >= 25 and (not LAST_DEVICE_HEARTBEAT or time.time() - LAST_DEVICE_HEARTBEAT > 12):
            self.reset_offline_pairing("O dispositivo saiu da rede privada. Conecte-o novamente para continuar.")
        stable_for = time.time() - self.offline_started_at if self.offline_started_at else 0
        if self.offline_hotspot_started and self.offline_stage == "network" and stable_for >= 8 and hotspot_has_client(self.local_ip):
            self.offline_stage = "app"
            self.offline_app_started_at = time.time()
            self.offline_status = "Dispositivo conectado à rede privada. Escaneie o QR Code de acesso."
            self._refresh_local_url()
            if self.current_page in ("overview", "connection"):
                self.render_overview() if self.current_page == "overview" else self.render_connection()
        self.after(1500, self.poll_offline_connection)

    def reset_offline_pairing(self, message="Conecte o dispositivo à rede privada do computador."):
        global ACTIVE_DEVICE_TOKEN, ACCESS_TOKEN_USED, LAST_DEVICE_HEARTBEAT, LAST_PHONE_SEEN
        AUTHORIZED_DEVICES.clear()
        ACTIVE_DEVICE_TOKEN = None
        ACCESS_TOKEN_USED = False
        LAST_DEVICE_HEARTBEAT = 0
        LAST_PHONE_SEEN = 0
        rotate_access_token()
        save_session({})
        self.session = {}
        self.offline_stage = "network"
        self.offline_app_started_at = 0
        self.offline_status = message
        clear_local_arp_cache()
        self._refresh_local_url()
        if self.current_page in ("overview", "connection"):
            self.render_overview() if self.current_page == "overview" else self.render_connection()

    def _refresh_local_url(self):
        global PUBLIC_URL, PUBLIC_BASE_URL
        PUBLIC_BASE_URL = f"http://{self.local_ip}:5000"
        PUBLIC_URL = f"{PUBLIC_BASE_URL}/?access={ACCESS_TOKEN}"
        self.url_text = PUBLIC_URL

    def poll_local_url(self):
        """Mantém o QR Code baseado no endereço privado desta estação."""
        global PUBLIC_URL, PUBLIC_BASE_URL
        current_base = f"http://{self.local_ip}:5000"
        if PUBLIC_BASE_URL != current_base:
            PUBLIC_BASE_URL = current_base
            PUBLIC_URL = f"{PUBLIC_BASE_URL}/?access={ACCESS_TOKEN}"
            self.url_text = PUBLIC_URL
        self.after(1000, self.poll_local_url)

    def close_app(self):
        global ACTIVE_DEVICE_TOKEN, ACCESS_TOKEN_USED, LAST_DEVICE_HEARTBEAT, LAST_PHONE_SEEN
        self.stop_all_gifs()
        AUTHORIZED_DEVICES.clear()
        ACTIVE_DEVICE_TOKEN = None
        ACCESS_TOKEN_USED = False
        LAST_DEVICE_HEARTBEAT = 0
        LAST_PHONE_SEEN = 0
        try:
            save_session({})
            if os.path.exists(SESSION_FILE):
                os.remove(SESSION_FILE)
        except OSError:
            pass
        for folder in (UPLOAD_FOLDER, OUTBOX_FOLDER):
            try:
                for name in os.listdir(folder):
                    if name.endswith(".part"):
                        os.remove(os.path.join(folder, name))
            except OSError:
                pass
        if getattr(self, "offline_hotspot_started", False):
            stop_windows_mobile_hotspot()
        self.destroy()

    def font(self, size=12, weight="normal"):
        return ctk.CTkFont(family="Poppins", size=size + 2, weight=weight)

    def load_asset(self, filename, size):
        key = f"{filename}:{size}"
        if key in self.asset_images:
            return self.asset_images[key]
        path = os.path.join(self.assets_dir, filename)
        if not os.path.exists(path):
            return None
        try:
            image = Image.open(path).convert("RGBA")
            visible = image.getbbox()
            if visible:
                image = image.crop(visible)
            image.thumbnail((size, size), Image.LANCZOS)
            canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            canvas.paste(image, ((size-image.width)//2, (size-image.height)//2), image)
            photo = ctk.CTkImage(light_image=canvas, dark_image=canvas, size=(size, size))
            self.asset_images[key] = photo
            return photo
        except Exception as error:
            print(f"Erro no asset {filename}: {error}")
            return None

    def load_gif_frames(self, filename, size):
        key = f"{filename}:{size}"
        if key in self.gif_frames:
            return self.gif_frames[key]
        path = os.path.join(self.assets_dir, filename)
        if not os.path.exists(path):
            return []
        try:
            frames = []
            with Image.open(path) as gif:
                for frame in ImageSequence.Iterator(gif):
                    image = frame.convert("RGBA")
                    image.thumbnail((size, size), Image.Resampling.LANCZOS)
                    frames.append(ImageTk.PhotoImage(image))
            self.gif_frames[key] = frames
            return frames
        except Exception as error:
            print(f"Erro no GIF {filename}: {error}")
            return []

    def start_frames(self, label, frames, key, interval=80):
        if not frames:
            return
        self.stop_gif(key)
        def animate(index=0):
            try:
                if not label.winfo_exists():
                    return
                label.configure(image=frames[index], text="")
                label.image = frames[index]
                self.gif_jobs[key] = self.after(interval, lambda: animate((index + 1) % len(frames)))
            except Exception:
                self.gif_jobs.pop(key, None)
        animate()
        label.gif_key = key

    def load_qr_gif_frames(self, size=178):
        key = f"qr:{self.url_text}:{size}"
        if key in self.qr_gif_frames:
            return self.qr_gif_frames[key]
        path = os.path.join(self.assets_dir, "carregando.gif")
        if not os.path.exists(path):
            return []
        frames = []
        try:
            qr_image = qrcode.make(self.url_text).convert("RGBA").resize((108, 108), Image.Resampling.NEAREST)
            with Image.open(path) as gif:
                for frame in ImageSequence.Iterator(gif):
                    base = frame.convert("RGBA").resize((size, size), Image.Resampling.LANCZOS)
                    # O QR é composto por último, ficando visualmente acima do GIF opaco.
                    base.alpha_composite(qr_image, ((size - 116) // 2, (size - 116) // 2))
                    frames.append(ImageTk.PhotoImage(base))
            self.qr_gif_frames[key] = frames
            return frames
        except Exception as error:
            print(f"Erro ao compor QR com carregando.gif: {error}")
            return []

    def start_gif(self, label, filename, size, interval=80):
        frames = self.load_gif_frames(filename, size)
        self.start_frames(label, frames, f"{id(label)}:{filename}", interval)

    def stop_gif(self, key):
        job = self.gif_jobs.pop(key, None)
        if job:
            try:
                self.after_cancel(job)
            except Exception:
                pass

    def stop_all_gifs(self):
        for key in list(self.gif_jobs):
            self.stop_gif(key)

    def make_card(self, parent, **kwargs):
        options = {"fg_color": self.colors["surface"], "corner_radius": 12,
                   "border_width": 1, "border_color": self.colors["border"]}
        options.update(kwargs)
        return ctk.CTkFrame(parent, **options)

    def build_shell(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)
        header = ctk.CTkFrame(self, height=70, fg_color=self.colors["blue"], corner_radius=0)
        header.grid(row=0, column=0, columnspan=2, sticky="nsew")
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)
        logo = self.load_asset("logo.png", 70)
        ctk.CTkLabel(header, image=logo, text="" if logo else "N", width=78, height=56,
                     fg_color="#FFFFFF" if not logo else "transparent", corner_radius=10).grid(row=0, column=0, padx=(22, 15), pady=7)
        top = ctk.CTkFrame(header, fg_color="transparent")
        top.grid(row=0, column=1, padx=5, sticky="w")
        items = [("Visão geral", "2.png", "overview", self.render_overview), ("Arquivos", "1.png", "files", self.render_files),
                 ("Conexão", "5.png", "connection", self.render_connection), ("Ferramentas", "8.png", "tools", self.render_tools)]
        for title, asset, page_key, action in items:
            button = ctk.CTkButton(top, text=title, image=self.load_asset(asset, 21), compound="left", width=98, height=31,
                          corner_radius=6, fg_color="transparent", hover_color="#7B69E2", text_color="#F2F0FF",
                          font=self.font(10, "bold" if page_key == self.current_page else "normal"), command=lambda key=page_key, fn=action: self.navigate(key, fn))
            button.pack(side="left", padx=2)
            self.nav_buttons[page_key] = button
        right = ctk.CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=2, padx=20, sticky="e")
        self.header_status_label = ctk.CTkLabel(right, text="●  SERVIDOR ONLINE", text_color="#BFF2D5", font=self.font(10, "bold"))
        self.header_status_label.pack(anchor="e")
        self.clock_label = ctk.CTkLabel(right, text="", text_color="#E1DCFF", font=self.font(9))
        self.clock_label.pack(anchor="e")

        self.sidebar = ctk.CTkFrame(self, width=238, fg_color=self.colors["sidebar"], corner_radius=0)
        self.sidebar.grid(row=1, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        ctk.CTkLabel(self.sidebar, text="ESTAÇÃO DE TRABALHO", text_color="#AAA4C7", font=self.font(10, "bold")).pack(anchor="w", padx=23, pady=(28, 18))
        self.create_sidebar_button("Visão geral", "2.png", "overview", self.render_overview)
        self.create_sidebar_button("Receber arquivos", "4.png", "files", self.render_files)
        self.create_sidebar_button("Conexão e QR Code", "5.png", "connection", self.render_connection)
        self.create_sidebar_button("Histórico", "3.png", "history", self.render_history)
        self.create_sidebar_button("Ferramentas", "8.png", "tools", self.render_tools)
        ctk.CTkFrame(self.sidebar, height=1, fg_color="#45456B").pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(self.sidebar, text="STATUS DO SERVIÇO", text_color="#AAA4C7", font=self.font(10, "bold")).pack(anchor="w", padx=23, pady=(0, 10))
        status = ctk.CTkFrame(self.sidebar, fg_color="#30305A", corner_radius=9)
        status.pack(fill="x", padx=16)
        self.server_dot_label = ctk.CTkLabel(status, text="", width=22, height=22, fg_color="transparent")
        self.server_dot_label.pack(side="left", padx=(12, 7), pady=11)
        self.start_gif(self.server_dot_label, "ponto.gif", 18, 100)
        st = ctk.CTkFrame(status, fg_color="transparent"); st.pack(side="left", pady=9)
        ctk.CTkLabel(st, text="Servidor local", text_color="#FFFFFF", font=self.font(11, "bold")).pack(anchor="w")
        ctk.CTkLabel(st, text="Porta 5000 ativa", text_color="#C6C0E4", font=self.font(10)).pack(anchor="w")
        self.content = ctk.CTkFrame(self, fg_color=self.colors["background"], corner_radius=0)
        self.content.grid(row=1, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(1, weight=0)
        self.content.grid_rowconfigure(2, weight=1)

    def create_sidebar_button(self, text, asset, page_key, command):
        button = ctk.CTkButton(self.sidebar, text=text, image=self.load_asset(asset, 21), compound="left", anchor="w",
                               height=39, corner_radius=7, fg_color="transparent", hover_color=self.colors["sidebar_hover"],
                               text_color="#C5D4E6", font=self.font(12, "bold" if page_key == self.current_page else "normal"), command=lambda key=page_key, fn=command: self.navigate(key, fn))
        button.pack(fill="x", padx=12, pady=3)
        self.nav_buttons[page_key] = button

    def navigate(self, page_key, action):
        self.current_page = page_key
        for key, button in self.nav_buttons.items():
            button.configure(font=self.font(12, "bold" if key == page_key else "normal"))
        action()

    def clear_content(self):
        # Mantém o ponto.gif do servidor ativo; reinicia apenas GIFs da tela atual.
        for key in list(self.gif_jobs):
            if not key.endswith(":ponto.gif"):
                self.stop_gif(key)
        for child in self.content.winfo_children():
            child.destroy()

    def page_header(self, title, subtitle, action_text=None, action=None, secondary_text=None, secondary_action=None):
        header = ctk.CTkFrame(self.content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=31, pady=(27, 18))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=title, text_color=self.colors["text"], font=self.font(25, "bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text=subtitle, text_color=self.colors["muted"], font=self.font(11)).grid(row=1, column=0, sticky="w", pady=(4, 0))
        if action_text and action:
            actions = ctk.CTkFrame(header, fg_color="transparent")
            actions.grid(row=0, column=1, rowspan=2, padx=(15, 0), sticky="e")
            ctk.CTkButton(actions, text=action_text, width=130, height=36, corner_radius=7, fg_color="#F0EEFF", hover_color="#E4DFFF", text_color=self.colors["blue"], font=self.font(10, "bold"), command=action).pack(side="left", padx=(0, 7))
            if secondary_text and secondary_action:
                ctk.CTkButton(actions, text=secondary_text, width=205, height=42, corner_radius=8, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], text_color="#FFFFFF", font=self.font(11, "bold"), command=secondary_action).pack(side="left")

    def render_overview(self):
        self.current_page = "overview"; self.clear_content()
        self.page_header("Visão geral", "Gerencie a conexão e receba arquivos do seu dispositivo móvel.", "Escolher pasta", self.choose_folder, "Enviar para dispositivo", self.add_files_for_device)
        stats = ctk.CTkFrame(self.content, fg_color="transparent"); stats.grid(row=1, column=0, sticky="ew", padx=31, pady=(0, 16))
        for i in range(4): stats.grid_columnconfigure(i, weight=1)
        self.stat_card(stats, 0, "STATUS", "Online", "Servidor pronto", "#4CDE04")
        self.stat_card(stats, 1, "ENDEREÇO LOCAL", self.local_ip, "Porta 5000", self.colors["blue"])
        self.stat_card(stats, 2, "TIPOS ACEITOS", "Fotos, vídeos + docs", "Qualquer arquivo", self.colors["purple"])
        self.stat_card(stats, 3, "LIMITE DE ENVIO", "10 GB", "Por transferência", self.colors["orange"])
        self.overview_body = ctk.CTkFrame(self.content, fg_color="transparent"); self.overview_body.grid(row=2, column=0, sticky="nsew", padx=31, pady=(0, 25))
        self.overview_body.grid_columnconfigure(0, weight=5); self.overview_body.grid_columnconfigure(1, weight=6); self.overview_body.grid_rowconfigure(0, weight=1)
        self.create_qr_card(self.overview_body, 0)
        self.create_activity_card(self.overview_body, 1)

    def create_qr_card(self, parent, column):
        self.qr_complete_items = []
        card=self.make_card(parent); card.grid(row=0,column=column,sticky="nsew",padx=(0,10) if column==0 else (10,0))
        if self.session.get("connected"):
            self.create_connected_card(card)
            return
        network_stage = self.offline_stage == "network"
        qr_target = f"WIFI:T:WPA;S:{self.offline_ssid};P:{self.offline_password};;" if network_stage else self.url_text
        ctk.CTkLabel(card,text="1  CONECTE O DISPOSITIVO À REDE" if network_stage else "2  ABRA O NEXUSDROP",text_color=self.colors["muted"],font=self.font(10,"bold")).pack(anchor="w",padx=22,pady=(20,3))
        ctk.CTkLabel(card,text="Escaneie para conectar ao PC" if network_stage else "Escaneie para abrir a transferência",text_color=self.colors["text"],font=self.font(18,"bold")).pack(anchor="w",padx=22)
        ctk.CTkLabel(card,text=self.offline_status if network_stage else "O dispositivo já está na rede privada do computador.",text_color=self.colors["muted"],font=self.font(11),wraplength=400,justify="left").pack(anchor="w",padx=22,pady=(3,7))
        self.qr_stage=ctk.CTkFrame(card,width=190,height=190,fg_color="#FFFFFF",corner_radius=12); self.qr_stage.pack(pady=(0,3)); self.qr_stage.pack_propagate(False)
        self.qr_canvas=Canvas(self.qr_stage,width=190,height=190,bg="#FFFFFF",highlightthickness=0); self.qr_canvas.pack()
        self.qr_loading_label = ctk.CTkLabel(self.qr_stage, text="", fg_color="transparent")
        self.qr_loading_label.place(relx=0.5, rely=0.5, anchor="center")
        if self.network_online is not False and not network_stage:
            self.start_frames(self.qr_loading_label, self.load_qr_gif_frames(178), f"{id(self.qr_loading_label)}:qr", 70)
        qr=ImageTk.PhotoImage(qrcode.make(qr_target).resize((108,108), Image.Resampling.NEAREST)); self.qr_photo=qr
        self.qr_image_id=self.qr_canvas.create_image(95,95,image=qr); self.qr_arc=self.qr_canvas.create_arc(7,7,183,183,start=0,extent=300,style="arc",width=4,outline=self.colors["blue"],state="hidden")
        self.qr_status=ctk.CTkLabel(card,text="Aguardando conexão à rede..." if network_stage else "Aguardando acesso...",text_color=self.colors["blue"],font=self.font(10,"bold"),wraplength=270,justify="center"); self.qr_status.pack(pady=(0,3))
        ctk.CTkLabel(card,text="1. Conecte à rede  •  2. Escaneie para abrir" if network_stage else "🔒 Acesso local protegido por token",text_color=self.colors["green"],font=self.font(10,"bold"),wraplength=360,justify="center").pack(pady=(0,10))

    def create_connected_card(self, card):
        ctk.CTkLabel(card, text="DISPOSITIVO CONECTADO", text_color=self.colors["green"], font=self.font(10, "bold")).pack(anchor="w", padx=22, pady=(28, 5))
        ctk.CTkLabel(card, text="Conexão reconhecida", text_color=self.colors["text"], font=self.font(20, "bold")).pack(anchor="w", padx=22)
        ctk.CTkLabel(card, text="Esta sessão está salva e pronta para receber novos arquivos.", text_color=self.colors["muted"], font=self.font(11), wraplength=400).pack(anchor="w", padx=22, pady=(7, 18))
        self.connected_gif_label = ctk.CTkLabel(card, text="", fg_color="transparent")
        self.connected_gif_label.pack(pady=5)
        self.start_gif(self.connected_gif_label, "concluido.gif", 112, 100)
        ctk.CTkLabel(card, text=f"Reconhecido em {self.session.get('time', 'agora')}", text_color=self.colors["green"], font=self.font(11, "bold")).pack(pady=(6, 2))
        ctk.CTkLabel(card, text=f"IP do dispositivo: {self.session.get('ip', 'desconhecido')}", text_color=self.colors["muted"], font=self.font(10)).pack()
        ctk.CTkButton(card, text="Reconectar dispositivo", width=190, height=36, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], font=self.font(10, "bold"), command=self.reconnect).pack(pady=(18, 22))

    def reconnect(self):
        self.reset_offline_pairing("Reconexão iniciada. Conecte o dispositivo à rede privada.")

    def create_activity_card(self,parent,column):
        card=self.make_card(parent); card.grid(row=0,column=column,sticky="nsew",padx=(10,0))
        send_box = ctk.CTkFrame(card, fg_color="#F3F0FF", corner_radius=11)
        send_box.pack(fill="x", padx=18, pady=(18, 12))
        send_top = ctk.CTkFrame(send_box, fg_color="transparent")
        send_top.pack(fill="x", padx=13, pady=(11, 3))
        ctk.CTkLabel(send_top, text="ENVIAR PARA DISPOSITIVO", text_color=self.colors["blue"], font=self.font(10, "bold")).pack(side="left")
        ctk.CTkButton(send_top, text="Selecionar arquivos", width=150, height=34, corner_radius=7, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], text_color="#FFFFFF", font=self.font(10, "bold"), command=self.add_files_for_device).pack(side="right")
        self.pc_send_status = ctk.CTkLabel(send_box, text="Nenhum arquivo na fila", text_color=self.colors["muted"], font=self.font(10, "bold"))
        self.pc_send_status.pack(anchor="w", padx=13, pady=(4, 0))
        self.pc_send_detail = ctk.CTkLabel(send_box, text="Escolha um ou vários arquivos para disponibilizar no dispositivo.", text_color=self.colors["muted"], font=self.font(9), wraplength=390, justify="left")
        self.pc_send_detail.pack(anchor="w", padx=13, pady=(2, 5))
        self.pc_send_bar = ctk.CTkProgressBar(send_box, height=6, corner_radius=3, mode="determinate", progress_color=self.colors["blue"], fg_color="#DAD4F5")
        self.pc_send_bar.set(0)
        self.pc_send_bar.pack(fill="x", padx=13, pady=(0, 11))
        ctk.CTkLabel(card,text="ATIVIDADE RECENTE",text_color=self.colors["muted"],font=self.font(10,"bold")).pack(anchor="w",padx=20,pady=(20,6))
        self.activity_title=ctk.CTkLabel(card,text="Tudo pronto para receber",text_color=self.colors["text"],font=self.font(17,"bold")); self.activity_title.pack(anchor="w",padx=20)
        self.transfer_detail=ctk.CTkLabel(card,text="Aguardando um novo envio pelo dispositivo.",text_color=self.colors["muted"],font=self.font(11),wraplength=440,justify="left"); self.transfer_detail.pack(anchor="w",padx=20,pady=(6,15))
        self.receive_progress=ctk.CTkProgressBar(card,height=8,corner_radius=4,mode="determinate",progress_color=self.colors["blue"],fg_color="#DCD8F4")
        self.receive_progress.set(0)
        self.receive_progress.pack(fill="x",padx=20,pady=(0,8))
        self.transfer_status=ctk.CTkLabel(card,text="Aguardando envio",text_color=self.colors["blue"],font=self.font(11,"bold")); self.transfer_status.pack(anchor="w",padx=20,pady=5)
        self.received_actions_frame=ctk.CTkFrame(card,fg_color="transparent")
        self.received_actions_frame.pack(fill="x",padx=20,pady=(4,5))
        ctk.CTkButton(card,text="Abrir pasta de recebidos",image=self.load_asset("1.png",20),compound="left",height=37,fg_color=self.colors["blue"],hover_color=self.colors["blue_dark"],font=self.font(10,"bold"),command=self.open_folder).pack(fill="x",padx=20,pady=(10,20))

    def render_files(self):
        self.current_page = "files"
        self.clear_content()
        self.page_header("Arquivos recebidos", "Veja e abra rapidamente os arquivos salvos pelo dispositivo.", "Escolher pasta", self.choose_folder)
        body = ctk.CTkFrame(self.content, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=31, pady=(0, 25))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        card = self.make_card(body)
        card.grid(row=0, column=0, sticky="nsew")
        ctk.CTkLabel(card, text="DIRETÓRIO ATUAL", text_color=self.colors["muted"], font=self.font(10, "bold")).pack(anchor="w", padx=22, pady=(22, 4))
        current_folder = active_device_folder(UPLOAD_FOLDER)
        ctk.CTkLabel(card, text=current_folder, text_color=self.colors["text"], font=self.font(12, "bold"), wraplength=800).pack(anchor="w", padx=22)
        file_actions = ctk.CTkFrame(card, fg_color="transparent")
        file_actions.pack(anchor="w", padx=22, pady=(12, 18))
        ctk.CTkButton(file_actions, text="Abrir pasta no Windows", width=190, height=35, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], font=self.font(10, "bold"), command=self.open_folder).pack(side="left", padx=(0, 8))
        ctk.CTkButton(file_actions, text="Excluir histórico", width=145, height=35, fg_color="#FCEAEC", hover_color="#F7D8DE", text_color="#B94359", font=self.font(10, "bold"), command=self.clear_history).pack(side="left")
        files = []
        try:
            files = sorted([name for name in os.listdir(current_folder) if os.path.isfile(os.path.join(current_folder, name))], key=lambda name: os.path.getmtime(os.path.join(current_folder, name)), reverse=True)
        except OSError:
            pass
        ctk.CTkLabel(card, text=f"{len(files)} arquivo(s) encontrado(s)", text_color=self.colors["muted"], font=self.font(11, "bold")).pack(anchor="w", padx=22, pady=(5, 6))
        scroll = ctk.CTkScrollableFrame(card, fg_color="#FAF9FE", corner_radius=8, height=300)
        scroll.pack(fill="both", expand=True, padx=22, pady=(0, 22))
        if not files:
            ctk.CTkLabel(scroll, text="Nenhum arquivo recebido ainda.", text_color=self.colors["muted"], font=self.font(12)).pack(pady=35)
        else:
            for name in files[:100]:
                row = ctk.CTkFrame(scroll, fg_color="#FFFFFF", corner_radius=7)
                row.pack(fill="x", padx=5, pady=4)
                ctk.CTkLabel(row, text=name, text_color=self.colors["text"], font=self.font(11, "bold"), anchor="w", justify="left", wraplength=560).pack(side="left", fill="x", expand=True, padx=12, pady=9)
                ctk.CTkButton(row, text="Abrir", width=62, height=27, fg_color="#F0EEFF", hover_color="#E4DFFF", text_color=self.colors["blue"], font=self.font(9, "bold"), command=lambda n=name: self.open_file(n)).pack(side="right", padx=8)

    def open_file(self, filename):
        try:
            os.startfile(os.path.join(active_device_folder(UPLOAD_FOLDER), filename))
        except Exception as error:
            self.show_notice(f"Não foi possível abrir: {error}")

    def render_connection(self):
        self.current_page="connection"; self.clear_content()
        self.page_header("Conexão e QR Code","A conexão só pode ser iniciada pelo escaneamento do QR Code no dispositivo móvel.")
        area=ctk.CTkFrame(self.content,fg_color="transparent"); area.grid(row=1,column=0,sticky="nsew",padx=31,pady=(0,25)); area.grid_columnconfigure(0,weight=1); area.grid_columnconfigure(1,weight=1); area.grid_rowconfigure(0,weight=1)
        self.create_qr_card(area,0)
        info=self.make_card(area); info.grid(row=0,column=1,sticky="nsew",padx=(10,0))
        connected = bool(self.session.get("connected"))
        ctk.CTkLabel(info,text="MONITORAMENTO DA CONEXÃO",text_color=self.colors["muted"],font=self.font(10,"bold")).pack(anchor="w",padx=22,pady=(22,8))
        ctk.CTkLabel(info,text="Dispositivo conectado" if connected else "Escaneie o QR Code pelo celular",text_color=self.colors["text"],font=self.font(18,"bold")).pack(anchor="w",padx=22)
        ctk.CTkLabel(info,text="Sessão reconhecida e pronta para novos envios." if connected else "Quando o celular abrir a página mobile, o programa mostrará uma confirmação verde e registrará o aparelho.",text_color=self.colors["muted"],font=self.font(11),wraplength=400,justify="left").pack(anchor="w",padx=22,pady=(7,18))
        self.connection_state=ctk.CTkLabel(info,text="● Dispositivo conectado" if connected else "● Aguardando conexão",text_color=self.colors["green"] if connected else self.colors["blue"],font=self.font(13,"bold")); self.connection_state.pack(anchor="w",padx=22,pady=10)
        for label,value in [("Acesso","Somente por QR Code"),("Porta","5000"),("Rede","Somente dispositivo móvel autorizado")]:
            row=ctk.CTkFrame(info,fg_color="#FAF9FE",corner_radius=7,height=38); row.pack(fill="x",padx=22,pady=4); row.pack_propagate(False)
            ctk.CTkLabel(row,text=label,text_color=self.colors["muted"],font=self.font(10)).pack(side="left",padx=12); ctk.CTkLabel(row,text=value,text_color=self.colors["text"],font=self.font(10,"bold")).pack(side="right",padx=12)

    def render_history(self):
        self.current_page="history"; self.clear_content()
        self.page_header("Histórico de transferências","Registros reais de escaneamentos e arquivos recebidos.","Atualizar",self.render_history)
        wrapper=ctk.CTkFrame(self.content,fg_color="transparent"); wrapper.grid(row=1,column=0,sticky="nsew",padx=31,pady=(0,25)); wrapper.grid_columnconfigure(0,weight=1); wrapper.grid_rowconfigure(0,weight=1)
        scroll=ctk.CTkScrollableFrame(wrapper,fg_color="#FFFFFF",corner_radius=12); scroll.grid(row=0,column=0,sticky="nsew")
        records=load_history()
        if not records:
            ctk.CTkLabel(scroll,text="Nenhuma atividade registrada ainda",text_color=self.colors["text"],font=self.font(17,"bold")).pack(pady=(45,5))
            ctk.CTkLabel(scroll,text="Escaneie o QR Code e envie um arquivo pelo dispositivo móvel.",text_color=self.colors["muted"],font=self.font(11)).pack(pady=(0,45))
            return
        for record in reversed(records[-100:]):
            self.history_row(scroll,record)
        ctk.CTkButton(wrapper,text="Limpar histórico",width=140,height=34,fg_color="#FCEAEC",hover_color="#F7D8DE",text_color="#B94359",font=self.font(10,"bold"),command=self.clear_history).grid(row=1,column=0,sticky="e",pady=(10,0))

    def history_row(self,parent,record):
        row=ctk.CTkFrame(parent,fg_color="#FAF9FE",corner_radius=9); row.pack(fill="x",padx=10,pady=5)
        kind="Escaneamento" if record.get("type")=="scan" else "Arquivo recebido"
        files=record.get("files", "QR Code reconhecido")
        text=ctk.CTkFrame(row,fg_color="transparent"); text.pack(side="left",fill="x",expand=True,padx=13,pady=10)
        ctk.CTkLabel(text,text=kind,text_color=self.colors["text"],font=self.font(11,"bold")).pack(anchor="w")
        ctk.CTkLabel(text,text=str(files),text_color=self.colors["muted"],font=self.font(10),wraplength=650,justify="left").pack(anchor="w",pady=(3,0))
        meta=f"{record.get('time','')}  •  IP {record.get('ip','desconhecido')}"
        ctk.CTkLabel(row,text=meta,text_color=self.colors["muted"],font=self.font(9)).pack(side="right",padx=13)

    def render_tools(self):
        self.current_page="tools"; self.clear_content(); self.page_header("Ferramentas","Ações úteis para administrar sua estação.")
        body=ctk.CTkFrame(self.content,fg_color="transparent"); body.grid(row=1,column=0,sticky="nsew",padx=31,pady=(0,25)); body.grid_columnconfigure(0,weight=1); body.grid_columnconfigure(1,weight=1)
        tools=[("Abrir pasta de recebidos","Acessar imediatamente o diretório atual",self.open_folder,self.colors["blue"]),("Exportar histórico","Salvar os registros em um arquivo TXT",self.export_history,self.colors["orange"]),
                 ("Enviar arquivos para o dispositivo","Escolher arquivos do PC para baixar no dispositivo",self.add_files_for_device,self.colors["coral"]),
                 ("Modo Seguro Offline","Criar uma rede Wi-Fi privada pelo PC, sem internet",self.open_offline_mode,self.colors["green"])]
        for i,(title,desc,action,color) in enumerate(tools):
            card=self.make_card(body); card.grid(row=i//2,column=i%2,sticky="ew",padx=6,pady=6)
            ctk.CTkLabel(card,text=title,text_color=self.colors["text"],font=self.font(14,"bold")).pack(anchor="w",padx=18,pady=(18,5))
            ctk.CTkLabel(card,text=desc,text_color=self.colors["muted"],font=self.font(10),wraplength=330,justify="left").pack(anchor="w",padx=18)
            ctk.CTkButton(card,text="Executar",height=34,fg_color=color,hover_color=self.colors["blue_dark"],font=self.font(10,"bold"),command=action).pack(anchor="w",padx=18,pady=(15,18))

    def stat_card(self,parent,column,title,value,subtitle,color):
        card=ctk.CTkFrame(parent,fg_color=color,corner_radius=10); card.grid(row=0,column=column,sticky="ew",padx=5)
        ctk.CTkLabel(card,text=title,text_color="#FFFFFF",font=self.font(9,"bold")).pack(anchor="w",padx=14,pady=(12,3))
        value_label=ctk.CTkLabel(card,text=value,text_color="#FFFFFF",font=self.font(15,"bold")); value_label.pack(anchor="w",padx=14)
        subtitle_label=ctk.CTkLabel(card,text=subtitle,text_color="#FFFFFF",font=self.font(10)); subtitle_label.pack(anchor="w",padx=14,pady=(2,12))
        if title == "STATUS":
            self.status_card = card
            self.status_value_label = value_label
            self.status_subtitle_label = subtitle_label

    def choose_folder(self):
        global UPLOAD_FOLDER
        selected=filedialog.askdirectory(title="Escolha a pasta para salvar os arquivos",initialdir=UPLOAD_FOLDER)
        if selected:
            UPLOAD_FOLDER=os.path.abspath(selected); os.makedirs(UPLOAD_FOLDER,exist_ok=True); self.show_notice("Diretório atualizado")
            if self.current_page=="files": self.render_files()

    def open_folder(self):
        try: os.startfile(active_device_folder(UPLOAD_FOLDER))
        except Exception as error: self.show_notice(f"Não foi possível abrir: {error}")

    def open_received_file(self, filename):
        safe_name = secure_filename(os.path.basename(filename))
        folder = os.path.realpath(active_device_folder(UPLOAD_FOLDER))
        target = os.path.realpath(os.path.join(folder, safe_name))
        if not safe_name or os.path.commonpath([folder, target]) != folder or not os.path.isfile(target):
            self.show_notice("Arquivo não encontrado")
            return
        try:
            os.startfile(target)
        except Exception as error:
            self.show_notice(f"Não foi possível abrir o arquivo: {error}")

    def show_received_file_action(self, filename):
        if not hasattr(self, "received_actions_frame") or not self.received_actions_frame.winfo_exists():
            return
        row = ctk.CTkFrame(self.received_actions_frame, fg_color="#F1FAF6", corner_radius=8)
        row.pack(fill="x", pady=3)
        label = ctk.CTkLabel(row, text=f"Recebido: {filename}", text_color=self.colors["green"], font=self.font(10, "bold"), wraplength=300, justify="left", anchor="w")
        label.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=7)
        ctk.CTkButton(row, text="Abrir", width=58, height=28, corner_radius=6, fg_color=self.colors["green"], hover_color="#167B5A", text_color="#FFFFFF", font=self.font(9, "bold"), command=lambda name=filename: self.open_received_file(name)).pack(side="right", padx=(3, 8), pady=5)
        self.received_action_rows.append(row)

        def remove_row():
            try:
                if row.winfo_exists():
                    row.destroy()
                if row in self.received_action_rows:
                    self.received_action_rows.remove(row)
            except Exception:
                pass
        self.after(6500, remove_row)

    def add_files_for_device(self):
        selected = filedialog.askopenfilenames(title="Escolha os arquivos para enviar ao dispositivo")
        if not selected:
            return
        if not ACTIVE_DEVICE_TOKEN:
            self.show_notice("Escaneie o QR Code antes de enviar arquivos")
            return
        target_folder = active_device_folder(OUTBOX_FOLDER)
        copied = 0
        total = len(selected)
        if self.current_page == "overview" and hasattr(self, "pc_send_status"):
            self.pc_send_status.configure(text="Preparando arquivos...", text_color=self.colors["blue"])
            self.pc_send_detail.configure(text=f"Copiando 0 de {total} arquivo(s) para a fila do dispositivo.")
            self.pc_send_bar.set(0)
            self.update_idletasks()
        for source in selected:
            try:
                name = os.path.basename(source)
                destination = os.path.join(target_folder, name)
                stem, extension = os.path.splitext(name)
                counter = 1
                while os.path.exists(destination):
                    destination = os.path.join(target_folder, f"{stem}_{counter}{extension}")
                    counter += 1
                shutil.copy2(source, destination)
                copied += 1
                if self.current_page == "overview" and hasattr(self, "pc_send_status"):
                    self.pc_send_status.configure(text="Enviando para a fila...", text_color=self.colors["blue"])
                    self.pc_send_detail.configure(text=f"Copiando {copied} de {total}: {name}")
                    self.pc_send_bar.set(copied / total)
                    self.update_idletasks()
            except OSError as error:
                print(f"Não foi possível adicionar {source}: {error}")
        if self.current_page == "overview" and hasattr(self, "pc_send_status"):
            self.pc_send_status.configure(text=f"{copied} arquivo(s) pronto(s) para o dispositivo", text_color=self.colors["green"] if copied else self.colors["coral"])
            self.pc_send_detail.configure(text="Abra a página no dispositivo e toque em Baixar na seção Arquivos do computador." if copied else "Nenhum arquivo foi adicionado.")
            self.pc_send_bar.set(1 if copied else 0)
        self.show_notice(f"{copied} arquivo(s) disponível(is) no dispositivo")

    def copy_url(self):
        if not PUBLIC_URL:
            self.show_notice("Endereço local indisponível")
            return
        self.clipboard_clear(); self.clipboard_append(self.url_text); self.update(); self.show_notice("Endereço copiado")

    def open_mobile_local(self):
        if not PUBLIC_URL:
            self.show_notice("Endereço local indisponível")
            return
        import webbrowser; webbrowser.open(self.url_text); self.show_notice("Página mobile aberta no navegador")

    def open_hotspot_settings(self):
        if os.name != "nt":
            self.show_notice("Disponível somente no Windows")
            return
        try:
            os.startfile("ms-settings:network-mobilehotspot")
        except Exception as error:
            self.show_notice(f"Não foi possível abrir as configurações: {error}")

    def start_offline_mode(self, ssid_entry, password_entry, window, status_label, automatic=False):
        ssid = ssid_entry.get().strip()
        password = password_entry.get().strip()
        if not ssid or len(password) < 8:
            status_label.configure(text="Informe o nome da rede e uma senha WPA2 com pelo menos 8 caracteres.", text_color=self.colors["coral"])
            return
        status_label.configure(text="Ativando o Hotspot Móvel do Windows...", text_color=self.colors["blue"])
        window.update_idletasks()
        ok, message = configure_legacy_windows_hotspot(ssid, password)
        if not ok:
            if automatic:
                status_label.configure(text="Este adaptador não permite configurar SSID e senha automaticamente.\nAbra as configurações do Windows, defina esses dados e clique novamente.", text_color=self.colors["coral"])
                return
            # Em drivers modernos o Hosted Network foi removido; nesse caso o
            # Windows só permite iniciar o hotspot já configurado no sistema.
            ok, message = start_windows_mobile_hotspot()
        if not ok:
            status_label.configure(text=f"Ativação automática indisponível neste adaptador.\n{message}\nAbra as configurações e ative o Hotspot Móvel.", text_color=self.colors["coral"])
            return
        self.offline_hotspot_started = True
        time.sleep(1.0)
        self.local_ip = detect_hotspot_ip(self.local_ip)
        global PUBLIC_BASE_URL, PUBLIC_URL
        PUBLIC_BASE_URL = f"http://{self.local_ip}:5000"
        PUBLIC_URL = f"{PUBLIC_BASE_URL}/?access={ACCESS_TOKEN}"
        self.url_text = PUBLIC_URL
        wifi_payload = f"WIFI:T:WPA;S:{ssid};P:{password};;"
        try:
            wifi_image = qrcode.make(wifi_payload).convert("RGB").resize((210, 210), Image.Resampling.NEAREST)
            app_image = qrcode.make(PUBLIC_URL).convert("RGB").resize((210, 210), Image.Resampling.NEAREST)
            wifi_photo = ctk.CTkImage(light_image=wifi_image, dark_image=wifi_image, size=(210, 210))
            app_photo = ctk.CTkImage(light_image=app_image, dark_image=app_image, size=(210, 210))
            for child in window.winfo_children():
                child.destroy()
            ctk.CTkLabel(window, text="Modo Seguro Offline ativo", text_color=self.colors["green"], font=self.font(18, "bold")).pack(pady=(20, 4))
            ctk.CTkLabel(window, text=f"Rede: {ssid}\nIP local do NexusDrop: {self.local_ip}:5000", text_color=self.colors["muted"], font=self.font(11), justify="center").pack(pady=(0, 12))
            body = ctk.CTkFrame(window, fg_color="transparent"); body.pack(fill="both", expand=True, padx=20)
            left = ctk.CTkFrame(body, fg_color="#F7F5FF", corner_radius=12); left.pack(side="left", fill="both", expand=True, padx=(0, 6))
            ctk.CTkLabel(left, text="1  ENTRAR NA REDE", text_color=self.colors["blue"], font=self.font(11, "bold")).pack(pady=(14, 5))
            ctk.CTkLabel(left, image=wifi_photo, text="").pack(pady=5)
            ctk.CTkLabel(left, text="Escaneie com a câmera para conectar o celular ao Wi-Fi do PC.", text_color=self.colors["muted"], font=self.font(9), wraplength=230, justify="center").pack(padx=12, pady=(3, 14))
            right = ctk.CTkFrame(body, fg_color="#F7F5FF", corner_radius=12); right.pack(side="right", fill="both", expand=True, padx=(6, 0))
            ctk.CTkLabel(right, text="2  ABRIR NEXUSDROP", text_color=self.colors["blue"], font=self.font(11, "bold")).pack(pady=(14, 5))
            ctk.CTkLabel(right, image=app_photo, text="").pack(pady=5)
            ctk.CTkLabel(right, text="Depois de entrar na rede, escaneie este QR Code.", text_color=self.colors["muted"], font=self.font(9), wraplength=230, justify="center").pack(padx=12, pady=(3, 14))
            window._qr_refs = (wifi_photo, app_photo)
            ctk.CTkButton(window, text="Fechar", width=130, height=34, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], font=self.font(10, "bold"), command=window.destroy).pack(pady=(12, 18))
            if self.current_page == "overview": self.render_overview()
            elif self.current_page == "connection": self.render_connection()
        except Exception as error:
            status_label.configure(text=f"Não foi possível gerar os QR Codes: {error}", text_color=self.colors["coral"])

    def open_offline_mode(self):
        window = ctk.CTkToplevel(self)
        window.title("Modo Seguro Offline — NexusDrop")
        window.geometry("650x620")
        window.minsize(620, 580)
        window.transient(self)
        window.grab_set()
        ctk.CTkLabel(window, text="Criar conexão offline", text_color=self.colors["text"], font=self.font(20, "bold")).pack(pady=(22, 4))
        ctk.CTkLabel(window, text="O celular entrará em uma rede Wi-Fi privada criada pelo Windows, sem internet ou Cloudflare.", text_color=self.colors["muted"], font=self.font(10), wraplength=560, justify="center").pack(pady=(0, 16))
        form = ctk.CTkFrame(window, fg_color="#F7F5FF", corner_radius=12); form.pack(fill="x", padx=28, pady=5)
        ctk.CTkLabel(form, text="Use exatamente o nome e a senha configurados no Hotspot Móvel do Windows.", text_color=self.colors["text"], font=self.font(10, "bold"), wraplength=530, justify="left").pack(anchor="w", padx=16, pady=(14, 10))
        ctk.CTkLabel(form, text="Nome da rede Wi-Fi (SSID)", text_color=self.colors["muted"], font=self.font(10, "bold")).pack(anchor="w", padx=16)
        ssid_entry = ctk.CTkEntry(form, height=35, placeholder_text="Ex.: NexusDrop-Offline"); ssid_entry.pack(fill="x", padx=16, pady=(4, 10)); ssid_entry.insert(0, "NexusDrop-Offline")
        ctk.CTkLabel(form, text="Senha da rede Wi-Fi", text_color=self.colors["muted"], font=self.font(10, "bold")).pack(anchor="w", padx=16)
        password_entry = ctk.CTkEntry(form, height=35, show="•", placeholder_text="Mínimo de 8 caracteres"); password_entry.pack(fill="x", padx=16, pady=(4, 14))
        generated_ssid = f"NexusDrop-Offline-{secrets.token_hex(2).upper()}"
        generated_password = f"Nexus-{secrets.token_urlsafe(10)}"
        ssid_entry.delete(0, "end"); ssid_entry.insert(0, generated_ssid)
        password_entry.insert(0, generated_password)
        status = ctk.CTkLabel(window, text="Se ainda não configurou o hotspot, abra as configurações primeiro.", text_color=self.colors["muted"], font=self.font(10), wraplength=560, justify="center"); status.pack(pady=(14, 8))
        buttons = ctk.CTkFrame(window, fg_color="transparent"); buttons.pack(pady=6)
        ctk.CTkButton(buttons, text="Abrir configurações do Windows", width=220, height=36, fg_color="#EEEAFD", hover_color="#DED7FA", text_color=self.colors["blue"], font=self.font(10, "bold"), command=self.open_hotspot_settings).pack(side="left", padx=5)
        ctk.CTkButton(buttons, text="Ativar e gerar QR Codes", width=190, height=36, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], font=self.font(10, "bold"), command=lambda: self.start_offline_mode(ssid_entry, password_entry, window, status)).pack(side="left", padx=5)
        self.after(350, lambda: self.start_offline_mode(ssid_entry, password_entry, window, status, automatic=True))

    def export_history(self):
        target=filedialog.asksaveasfilename(title="Exportar histórico",defaultextension=".txt",filetypes=[("Arquivo de texto","*.txt")])
        if target:
            with open(target,"w",encoding="utf-8") as file:
                for item in load_history(): file.write(f"{item.get('time')} | {item.get('type')} | {item.get('ip')} | {item.get('files','QR Code')}\n")
            self.show_notice("Histórico exportado")

    def clear_history(self):
        from tkinter import messagebox
        if not load_history():
            self.show_notice("O histórico já está vazio")
            return
        if not messagebox.askyesno("Excluir histórico", "Deseja apagar todos os registros do histórico?"):
            return
        save_history([])
        if self.current_page == "history":
            self.render_history()
        else:
            self.show_notice("Histórico excluído")

    def show_overview_notice(self): self.show_notice("Você já está na visão geral")

    def update_clock(self):
        import datetime
        if hasattr(self,"clock_label"): self.clock_label.configure(text=datetime.datetime.now().strftime("%d/%m/%Y  •  %H:%M"))
        self.after(1000,self.update_clock)

    def is_network_online(self):
        # No Windows, consulta diretamente o estado do adaptador Wi-Fi.
        if os.name == "nt":
            try:
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=2,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                output = result.stdout.lower()
                # O Windows pode devolver vários espaços antes dos dois-pontos.
                normalized = re.sub(r"\s+", " ", output).strip()
                connected_words = ("state : connected", "estado : conectado")
                disconnected_words = ("state : disconnected", "estado : desconectado")
                if any(word in normalized for word in connected_words):
                    return True
                if any(word in normalized for word in disconnected_words):
                    return False
                # Se o netsh respondeu, mas não encontrou uma interface conectada,
                # consideramos o Wi-Fi indisponível em vez de usar um IP antigo em cache.
                if normalized:
                    return False
            except (OSError, subprocess.SubprocessError):
                pass

        # Fallback sem consultar nenhum endereço externo.
        try:
            addresses = socket.gethostbyname_ex(socket.gethostname())[2]
            return any(address not in ("", "0.0.0.0", "127.0.0.1") for address in addresses)
        except OSError:
            return False

    def update_network_status(self):
        online = self.offline_hotspot_started or self.is_network_online()
        changed = online != self.network_online
        self.network_online = online
        if online:
            if hasattr(self, "header_status_label"):
                self.header_status_label.configure(text="●  SERVIDOR ONLINE", text_color="#BFF2D5")
            if hasattr(self, "server_dot_label"):
                if changed:
                    self.start_gif(self.server_dot_label, "ponto.gif", 18, 100)
                self.server_dot_label.configure(text="")
            if hasattr(self, "qr_loading_label") and self.qr_loading_label.winfo_exists():
                if changed:
                    self.start_frames(self.qr_loading_label, self.load_qr_gif_frames(178), f"{id(self.qr_loading_label)}:qr", 70)
                self.qr_loading_label.configure(text="")
            if hasattr(self, "status_card") and self.status_card.winfo_exists():
                self.status_card.configure(fg_color="#4CDE04")
                self.status_value_label.configure(text="Online")
                self.status_subtitle_label.configure(text="Servidor pronto")
        else:
            if hasattr(self, "header_status_label"):
                self.header_status_label.configure(text="●  SERVIDOR OFFLINE", text_color="#FFB1B1")
            if hasattr(self, "server_dot_label"):
                if changed:
                    self.stop_gif(f"{id(self.server_dot_label)}:ponto.gif")
                self.server_dot_label.configure(text="●", text_color="#FF4D5A", font=self.font(17, "bold"))
            if hasattr(self, "qr_loading_label") and self.qr_loading_label.winfo_exists():
                self.stop_gif(f"{id(self.qr_loading_label)}:qr")
                self.qr_loading_label.configure(image="", text="")
            if hasattr(self, "status_card") and self.status_card.winfo_exists():
                self.status_card.configure(fg_color="#D64545")
                self.status_value_label.configure(text="Offline")
                self.status_subtitle_label.configure(text="Wi-Fi desconectado")

    def poll_server_state(self):
        global LAST_PHONE_SEEN, LAST_UPLOAD_TIME, LAST_UPLOADED_FILE, TRANSFER_STATE
        if time.time() - self.last_network_check >= 2:
            self.last_network_check = time.time()
            self.update_network_status()
        if LAST_PHONE_SEEN > self.last_phone_seen:
            self.last_phone_seen=LAST_PHONE_SEEN
            latest_session = load_session()
            session_changed = latest_session.get("connected") != self.session.get("connected") or latest_session.get("time") != self.session.get("time")
            self.session = latest_session
            if session_changed and self.session.get("connected") and self.current_page in ("overview", "connection"):
                if self.current_page == "overview": self.render_overview()
                else: self.render_connection()
        if hasattr(self,"transfer_status") and TRANSFER_STATE.get("active"):
            percent = TRANSFER_STATE.get("percent", 0)
            amount = TRANSFER_STATE.get("files", 0)
            if hasattr(self, "receive_progress"):
                self.receive_progress.set(percent / 100)
            self.activity_title.configure(text="Recebendo arquivos...", text_color=self.colors["blue"])
            self.transfer_status.configure(text=f"Transferindo • {percent}%", text_color=self.colors["blue"])
            current_name = TRANSFER_STATE.get("name") or "Aguarde a conclusão."
            self.transfer_detail.configure(text=f"Recebendo {amount} arquivo(s) do dispositivo.\nArquivo atual: {current_name}")
        elif hasattr(self,"transfer_status") and LAST_UPLOAD_TIME > self.last_upload_time:
            self.last_upload_time=LAST_UPLOAD_TIME
            if hasattr(self, "receive_progress"):
                self.receive_progress.set(1)
            self.activity_title.configure(text="Arquivo recebido",text_color=self.colors["green"])
            self.transfer_status.configure(text="Envio concluído",text_color=self.colors["green"])
            self.transfer_detail.configure(text=f"Recebido com sucesso:\n{LAST_UPLOADED_FILE or 'Arquivo recebido'}")
            for filename in [item.strip() for item in (LAST_UPLOADED_FILE or "").split(",") if item.strip()]:
                self.show_received_file_action(filename)
        elif hasattr(self,"transfer_status") and self.current_page=="overview":
            if hasattr(self, "receive_progress"):
                self.receive_progress.set(0)
            self.transfer_status.configure(text="Aguardando envio",text_color=self.colors["blue"])
            self.transfer_detail.configure(text="Aguardando um novo envio pelo dispositivo.")
        # O anel agora é desenhado somente pelo carregando.gif.
        self.after(350,self.poll_server_state)

    def show_qr_success(self):
        if not hasattr(self,"qr_canvas") or self.qr_complete_items: return
        try:
            self.qr_canvas.itemconfigure(self.qr_image_id,state="hidden"); self.qr_canvas.itemconfigure(self.qr_arc,state="hidden")
        except Exception:
            return
        self.qr_complete_items=[self.qr_canvas.create_oval(48,48,142,142,fill=self.colors["green"],outline=self.colors["green"]),self.qr_canvas.create_line(69,95,88,114,fill="#FFFFFF",width=7),self.qr_canvas.create_line(88,114,124,74,fill="#FFFFFF",width=7)]
        self.qr_status.configure(text="Dispositivo reconhecido",text_color=self.colors["green"])
        if hasattr(self,"connection_state"): self.connection_state.configure(text="● Conexão reconhecida",text_color=self.colors["green"])
        self.after(2400,self.restore_qr)

    def restore_qr(self):
        if not hasattr(self,"qr_canvas"): return
        try:
            for item in self.qr_complete_items: self.qr_canvas.delete(item)
            self.qr_complete_items=[]; self.qr_canvas.itemconfigure(self.qr_image_id,state="normal"); self.qr_canvas.itemconfigure(self.qr_arc,state="hidden"); self.qr_status.configure(text="Aguardando reconhecimento\ndo dispositivo...",text_color=self.colors["blue"])
        except Exception:
            self.qr_complete_items=[]

    def show_notice(self,message):
        toast=ctk.CTkLabel(self,text=message,fg_color=self.colors["navy"],text_color="#FFFFFF",corner_radius=7,width=300,height=36,font=self.font(11,"bold")); toast.place(relx=.55,rely=.94,anchor="center"); self.after(2200,toast.destroy)


if __name__ == "__main__":
    allowed, access_message = check_app_access()
    if not allowed:
        try:
            from tkinter import messagebox
            messagebox.showwarning("NexusDrop", access_message)
        except Exception:
            print(access_message)
        sys.exit(0)
    server_thread=ServerThread(); server_thread.start()
    app_window=ProfessionalApp(); app_window.mainloop()
