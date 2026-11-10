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
from PIL import Image, ImageTk, ImageSequence
from tkinter import filedialog, Canvas
import time
from flask import Flask, request, render_template, send_from_directory, jsonify, make_response
from werkzeug.utils import secure_filename
import customtkinter as ctk

# =====================================================
# CONFIGURAÇÕES DO FLASK E UPLOAD
# =====================================================

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

# Token temporário desta execução. O IP sozinho não dá acesso ao servidor.
ACCESS_TOKEN = secrets.token_urlsafe(32)
AUTHORIZED_DEVICES = {}
ACTIVE_DEVICE_TOKEN = None
DEVICE_COOKIE = "nexus_device"


def is_authorized_device():
    device_token = request.cookies.get(DEVICE_COOKIE, "")
    return bool(device_token and device_token in AUTHORIZED_DEVICES)


def valid_access_token():
    supplied = request.args.get("access", "")
    return bool(supplied and hmac.compare_digest(supplied, ACCESS_TOKEN))


def access_denied():
    return "Acesso não autorizado. Escaneie o QR Code exibido pelo NexusDrop.", 403


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
    control = check_remote_control()
    if not control.get("active", True):
        return False, control.get("message") or "O NexusDrop está temporariamente desativado."
    if control.get("maintenance", False):
        return False, control.get("message") or "O NexusDrop está em manutenção. Tente novamente mais tarde."
    minimum = version_tuple(control.get("minimum_version", "0.0.0"))
    if version_tuple(APP_VERSION) < minimum:
        return False, control.get("message") or f"Atualize o NexusDrop para a versão {control.get('minimum_version')}."
    return True, "OK"


LAST_PHONE_SEEN = 0
LAST_UPLOAD_TIME = 0
LAST_UPLOADED_FILE = ""
TRANSFER_STATE = {"active": False, "percent": 0, "files": 0, "name": "", "speed": "0 MB/s"}
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
SESSION_FILE = os.path.join(DATA_DIR, "session.json")
UPLOAD_FOLDER = os.path.join(os.path.expanduser("~"), "Desktop", "RecebidosiPhone")
OUTBOX_FOLDER = os.path.join(os.path.expanduser("~"), "Desktop", "NexusDrop_Para_iPhone")
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
    # Cada dispositivo possui uma pasta própria; ../ continua bloqueado pelo Flask.
    return send_from_directory(active_device_folder(OUTBOX_FOLDER), filename, as_attachment=True)


@app.route("/transfer-status", methods=["POST"])
def transfer_status():
    global TRANSFER_STATE
    if not is_authorized_device():
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

@app.route("/", methods=["GET", "POST"])
def upload_file():
    global LAST_PHONE_SEEN, LAST_UPLOAD_TIME, LAST_UPLOADED_FILE, ACTIVE_DEVICE_TOKEN
    if request.method == "POST":
        if not is_authorized_device():
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
                    destination = os.path.join(UPLOAD_FOLDER, new_filename)
                    counter += 1
                file.save(destination)
                saved_names.append(os.path.basename(destination))
            LAST_UPLOADED_FILE = ", ".join(saved_names)
            TRANSFER_STATE.update({"active": False, "percent": 100, "files": len(saved_names), "name": LAST_UPLOADED_FILE, "speed": "Concluído"})
            LAST_UPLOAD_TIME = time.time()
            add_history({
                "type": "upload",
                "files": LAST_UPLOADED_FILE,
                "ip": request.remote_addr or "desconhecido",
                "device": request.headers.get("User-Agent", "iPhone"),
                "time": time.strftime("%d/%m/%Y %H:%M:%S")
            })
            return "Sucesso", 200
        except Exception as error:
            print("Erro:", error)
            return "Erro ao salvar", 500

    # O IP sozinho não é suficiente: a primeira abertura precisa do token do QR.
    if not is_authorized_device() and not valid_access_token():
        return access_denied()
    device_token = request.cookies.get(DEVICE_COOKIE)
    is_new_device = not device_token or device_token not in AUTHORIZED_DEVICES
    if is_new_device:
        # Apenas um iPhone fica autorizado por vez nesta estação.
        # Isso evita que dois dispositivos compartilhem a mesma fila.
        AUTHORIZED_DEVICES.clear()
        device_token = secrets.token_urlsafe(32)
        AUTHORIZED_DEVICES[device_token] = {
            "ip": request.remote_addr or "desconhecido",
            "created_at": time.time()
        }
        ACTIVE_DEVICE_TOKEN = device_token
    if is_new_device:
        LAST_PHONE_SEEN = time.time()
        scan_time = time.strftime("%d/%m/%Y %H:%M:%S")
        save_session({
            "connected": True,
            "ip": request.remote_addr or "desconhecido",
            "device": request.headers.get("User-Agent", "iPhone"),
            "time": scan_time
        })
        add_history({
            "type": "scan",
            "files": "QR Code reconhecido",
            "ip": request.remote_addr or "desconhecido",
            "device": request.headers.get("User-Agent", "iPhone"),
            "time": scan_time
        })
    response = make_response(render_template("mobile.html"))
    response.set_cookie(DEVICE_COOKIE, device_token, max_age=86400, httponly=True, samesite="Lax")
    return response

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class ServerThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
    def run(self):
        app.run(host="0.0.0.0", port=5000, threaded=True, use_reloader=False)


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
        ico_path = os.path.join(BASE_DIR, "assets", "icone.ico")
        png_path = os.path.join(BASE_DIR, "assets", "icone.png")
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
        self.url_text = f"http://{self.local_ip}:5000/?access={ACCESS_TOKEN}"
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
        self.current_page = "overview"
        self.nav_buttons = {}
        self.session = load_session()
        self.build_shell()
        self.render_overview()
        self.update_clock()
        self.poll_server_state()

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

    def load_qr_gif_frames(self, size=198):
        key = f"qr:{self.url_text}:{size}"
        if key in self.qr_gif_frames:
            return self.qr_gif_frames[key]
        path = os.path.join(self.assets_dir, "carregando.gif")
        if not os.path.exists(path):
            return []
        frames = []
        try:
            qr_image = qrcode.make(self.url_text).convert("RGBA").resize((116, 116), Image.Resampling.NEAREST)
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
        self.page_header("Visão geral", "Gerencie a conexão e receba arquivos do seu iPhone.", "Escolher pasta", self.choose_folder, "Enviar para iPhone", self.add_files_for_iphone)
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
        ctk.CTkLabel(card,text="CONECTE SEU IPHONE",text_color=self.colors["muted"],font=self.font(10,"bold")).pack(anchor="w",padx=22,pady=(20,3))
        ctk.CTkLabel(card,text="Escaneie para começar",text_color=self.colors["text"],font=self.font(18,"bold")).pack(anchor="w",padx=22)
        ctk.CTkLabel(card,text="Abra a câmera e aponte para o QR Code.",text_color=self.colors["muted"],font=self.font(11)).pack(anchor="w",padx=22,pady=(3,7))
        self.qr_stage=ctk.CTkFrame(card,width=210,height=210,fg_color="#FFFFFF",corner_radius=12); self.qr_stage.pack(pady=(0,6)); self.qr_stage.pack_propagate(False)
        self.qr_canvas=Canvas(self.qr_stage,width=210,height=210,bg="#FFFFFF",highlightthickness=0); self.qr_canvas.pack()
        self.qr_loading_label = ctk.CTkLabel(self.qr_stage, text="", fg_color="transparent")
        self.qr_loading_label.place(relx=0.5, rely=0.5, anchor="center")
        if self.network_online is not False:
            self.start_frames(self.qr_loading_label, self.load_qr_gif_frames(198), f"{id(self.qr_loading_label)}:qr", 70)
        qr=ImageTk.PhotoImage(qrcode.make(self.url_text).resize((116,116), Image.Resampling.NEAREST)); self.qr_photo=qr
        self.qr_image_id=self.qr_canvas.create_image(105,105,image=qr); self.qr_arc=self.qr_canvas.create_arc(7,7,203,203,start=0,extent=300,style="arc",width=4,outline=self.colors["blue"],state="hidden")
        self.qr_status=ctk.CTkLabel(card,text="Aguardando reconhecimento\ndo iPhone...",text_color=self.colors["blue"],font=self.font(10,"bold"),wraplength=230,justify="center"); self.qr_status.pack(pady=(0,5))
        line=ctk.CTkFrame(card,fg_color="transparent"); line.pack(fill="x",padx=20,pady=(0,17))
        entry=ctk.CTkEntry(line,height=35,fg_color="#F5F3FF",border_color=self.colors["border"],text_color=self.colors["blue"],font=self.font(10,"bold")); entry.insert(0,self.url_text); entry.configure(state="readonly"); entry.pack(side="left",fill="x",expand=True,padx=(0,6))
        ctk.CTkButton(line,text="Copiar",width=70,height=35,fg_color="#F0EEFF",hover_color="#E4DFFF",text_color=self.colors["blue"],font=self.font(10,"bold"),command=self.copy_url).pack(side="right")

    def create_connected_card(self, card):
        ctk.CTkLabel(card, text="IPHONE CONECTADO", text_color=self.colors["green"], font=self.font(10, "bold")).pack(anchor="w", padx=22, pady=(28, 5))
        ctk.CTkLabel(card, text="Conexão reconhecida", text_color=self.colors["text"], font=self.font(20, "bold")).pack(anchor="w", padx=22)
        ctk.CTkLabel(card, text="Esta sessão está salva e pronta para receber novos arquivos.", text_color=self.colors["muted"], font=self.font(11), wraplength=400).pack(anchor="w", padx=22, pady=(7, 18))
        self.connected_gif_label = ctk.CTkLabel(card, text="", fg_color="transparent")
        self.connected_gif_label.pack(pady=5)
        self.start_gif(self.connected_gif_label, "concluido.gif", 112, 100)
        ctk.CTkLabel(card, text=f"Reconhecido em {self.session.get('time', 'agora')}", text_color=self.colors["green"], font=self.font(11, "bold")).pack(pady=(6, 2))
        ctk.CTkLabel(card, text=f"IP do iPhone: {self.session.get('ip', 'desconhecido')}", text_color=self.colors["muted"], font=self.font(10)).pack()
        ctk.CTkButton(card, text="Reconectar outro iPhone", width=190, height=36, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], font=self.font(10, "bold"), command=self.reconnect).pack(pady=(18, 22))

    def reconnect(self):
        save_session({})
        self.session = {}
        self.render_connection()

    def create_activity_card(self,parent,column):
        card=self.make_card(parent); card.grid(row=0,column=column,sticky="nsew",padx=(10,0))
        send_box = ctk.CTkFrame(card, fg_color="#F3F0FF", corner_radius=11)
        send_box.pack(fill="x", padx=18, pady=(18, 12))
        send_top = ctk.CTkFrame(send_box, fg_color="transparent")
        send_top.pack(fill="x", padx=13, pady=(11, 3))
        ctk.CTkLabel(send_top, text="ENVIAR PARA IPHONE", text_color=self.colors["blue"], font=self.font(10, "bold")).pack(side="left")
        ctk.CTkButton(send_top, text="Selecionar arquivos", width=150, height=34, corner_radius=7, fg_color=self.colors["blue"], hover_color=self.colors["blue_dark"], text_color="#FFFFFF", font=self.font(10, "bold"), command=self.add_files_for_iphone).pack(side="right")
        self.pc_send_status = ctk.CTkLabel(send_box, text="Nenhum arquivo na fila", text_color=self.colors["muted"], font=self.font(10, "bold"))
        self.pc_send_status.pack(anchor="w", padx=13, pady=(4, 0))
        self.pc_send_detail = ctk.CTkLabel(send_box, text="Escolha um ou vários arquivos para disponibilizar no iPhone.", text_color=self.colors["muted"], font=self.font(9), wraplength=390, justify="left")
        self.pc_send_detail.pack(anchor="w", padx=13, pady=(2, 5))
        self.pc_send_bar = ctk.CTkProgressBar(send_box, height=6, corner_radius=3, mode="determinate", progress_color=self.colors["blue"], fg_color="#DAD4F5")
        self.pc_send_bar.set(0)
        self.pc_send_bar.pack(fill="x", padx=13, pady=(0, 11))
        ctk.CTkLabel(card,text="ATIVIDADE RECENTE",text_color=self.colors["muted"],font=self.font(10,"bold")).pack(anchor="w",padx=20,pady=(20,6))
        self.activity_title=ctk.CTkLabel(card,text="Tudo pronto para receber",text_color=self.colors["text"],font=self.font(17,"bold")); self.activity_title.pack(anchor="w",padx=20)
        self.transfer_detail=ctk.CTkLabel(card,text="Aguardando um novo envio pelo iPhone.",text_color=self.colors["muted"],font=self.font(11),wraplength=440,justify="left"); self.transfer_detail.pack(anchor="w",padx=20,pady=(6,15))
        self.transfer_status=ctk.CTkLabel(card,text="Aguardando envio",text_color=self.colors["blue"],font=self.font(11,"bold")); self.transfer_status.pack(anchor="w",padx=20,pady=5)
        self.transfer_bar=ctk.CTkFrame(card,height=5,corner_radius=3,fg_color="#DCD8F4"); self.transfer_bar.pack(fill="x",padx=20,pady=(4,15)); self.transfer_bar.pack_propagate(False)
        ctk.CTkButton(card,text="Abrir pasta de recebidos",image=self.load_asset("1.png",20),compound="left",height=37,fg_color=self.colors["blue"],hover_color=self.colors["blue_dark"],font=self.font(10,"bold"),command=self.open_folder).pack(fill="x",padx=20,pady=(10,20))

    def render_files(self):
        self.current_page = "files"
        self.clear_content()
        self.page_header("Arquivos recebidos", "Veja e abra rapidamente os arquivos salvos pelo iPhone.", "Escolher pasta", self.choose_folder)
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
        self.page_header("Conexão e QR Code","Acompanhe em tempo real quando um iPhone reconhecer o endereço.","Copiar endereço",self.copy_url)
        area=ctk.CTkFrame(self.content,fg_color="transparent"); area.grid(row=1,column=0,sticky="nsew",padx=31,pady=(0,25)); area.grid_columnconfigure(0,weight=1); area.grid_columnconfigure(1,weight=1); area.grid_rowconfigure(0,weight=1)
        self.create_qr_card(area,0)
        info=self.make_card(area); info.grid(row=0,column=1,sticky="nsew",padx=(10,0))
        connected = bool(self.session.get("connected"))
        ctk.CTkLabel(info,text="MONITORAMENTO DA CONEXÃO",text_color=self.colors["muted"],font=self.font(10,"bold")).pack(anchor="w",padx=22,pady=(22,8))
        ctk.CTkLabel(info,text="iPhone conectado" if connected else "Escaneie o QR Code pelo iPhone",text_color=self.colors["text"],font=self.font(18,"bold")).pack(anchor="w",padx=22)
        ctk.CTkLabel(info,text="Sessão reconhecida e pronta para novos envios." if connected else "Quando o celular abrir a página mobile, o programa mostrará uma confirmação verde e registrará o aparelho.",text_color=self.colors["muted"],font=self.font(11),wraplength=400,justify="left").pack(anchor="w",padx=22,pady=(7,18))
        self.connection_state=ctk.CTkLabel(info,text="● iPhone conectado" if connected else "● Aguardando conexão",text_color=self.colors["green"] if connected else self.colors["blue"],font=self.font(13,"bold")); self.connection_state.pack(anchor="w",padx=22,pady=10)
        for label,value in [("Endereço",self.url_text),("Porta","5000"),("Rede","Somente rede local")]:
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
            ctk.CTkLabel(scroll,text="Escaneie o QR Code e envie um arquivo pelo iPhone.",text_color=self.colors["muted"],font=self.font(11)).pack(pady=(0,45))
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
        tools=[("Abrir pasta de recebidos","Acessar imediatamente o diretório atual",self.open_folder,self.colors["blue"]),("Copiar endereço local","Copiar o endereço para compartilhar na rede",self.copy_url,self.colors["green"]),("Abrir página mobile","Testar a tela do celular neste computador",self.open_mobile_local,self.colors["purple"]),("Exportar histórico","Salvar os registros em um arquivo TXT",self.export_history,self.colors["orange"]),
                 ("Enviar arquivos para o iPhone","Escolher arquivos do PC para baixar no celular",self.add_files_for_iphone,self.colors["coral"])]
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

    def add_files_for_iphone(self):
        selected = filedialog.askopenfilenames(title="Escolha os arquivos para enviar ao iPhone")
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
            self.pc_send_detail.configure(text=f"Copiando 0 de {total} arquivo(s) para a fila do iPhone.")
            self.pc_send_bar.set(0)
            self.update_idletasks()
        for source in selected:
            try:
                name = os.path.basename(source)
                destination = os.path.join(target_folder, name)
                stem, extension = os.path.splitext(name)
                counter = 1
                while os.path.exists(destination):
                    destination = os.path.join(OUTBOX_FOLDER, f"{stem}_{counter}{extension}")
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
            self.pc_send_status.configure(text=f"{copied} arquivo(s) pronto(s) para o iPhone", text_color=self.colors["green"] if copied else self.colors["coral"])
            self.pc_send_detail.configure(text="Abra a página no iPhone e toque em Baixar na seção Arquivos do computador." if copied else "Nenhum arquivo foi adicionado.")
            self.pc_send_bar.set(1 if copied else 0)
        self.show_notice(f"{copied} arquivo(s) disponível(is) no iPhone")

    def copy_url(self):
        self.clipboard_clear(); self.clipboard_append(self.url_text); self.update(); self.show_notice("Endereço copiado")

    def open_mobile_local(self):
        import webbrowser; webbrowser.open(self.url_text); self.show_notice("Página mobile aberta no navegador")

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

        # Fallback para outros sistemas ou quando netsh não responder.
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(0.8)
            probe.connect(("8.8.8.8", 80))
            address = probe.getsockname()[0]
            probe.close()
            return address not in ("", "0.0.0.0", "127.0.0.1")
        except OSError:
            try:
                address = socket.gethostbyname(socket.gethostname())
                return address not in ("", "0.0.0.0", "127.0.0.1")
            except OSError:
                return False

    def update_network_status(self):
        online = self.is_network_online()
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
                    self.start_frames(self.qr_loading_label, self.load_qr_gif_frames(198), f"{id(self.qr_loading_label)}:qr", 70)
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
            self.session=load_session()
            if self.session.get("connected") and self.current_page in ("overview", "connection"):
                if self.current_page == "overview": self.render_overview()
                else: self.render_connection()
        if hasattr(self,"transfer_status") and TRANSFER_STATE.get("active"):
            percent = TRANSFER_STATE.get("percent", 0)
            amount = TRANSFER_STATE.get("files", 0)
            self.activity_title.configure(text="Recebendo arquivos...", text_color=self.colors["blue"])
            self.transfer_status.configure(text=f"Transferindo • {percent}%", text_color=self.colors["blue"])
            self.transfer_detail.configure(text=f"O iPhone está enviando {amount} arquivo(s). {TRANSFER_STATE.get('name') or 'Aguarde a conclusão.'}")
        elif hasattr(self,"transfer_status") and LAST_UPLOAD_TIME > self.last_upload_time:
            self.last_upload_time=LAST_UPLOAD_TIME; self.activity_title.configure(text="Arquivo recebido",text_color=self.colors["green"]); self.transfer_status.configure(text="Envio concluído",text_color=self.colors["green"]); self.transfer_detail.configure(text=LAST_UPLOADED_FILE or "Arquivo recebido")
        elif hasattr(self,"transfer_status") and self.current_page=="overview":
            self.transfer_status.configure(text="Aguardando envio",text_color=self.colors["blue"])
            self.transfer_detail.configure(text="Aguardando um novo envio pelo iPhone.")
        # O anel agora é desenhado somente pelo carregando.gif.
        self.after(350,self.poll_server_state)

    def show_qr_success(self):
        if not hasattr(self,"qr_canvas") or self.qr_complete_items: return
        try:
            self.qr_canvas.itemconfigure(self.qr_image_id,state="hidden"); self.qr_canvas.itemconfigure(self.qr_arc,state="hidden")
        except Exception:
            return
        self.qr_complete_items=[self.qr_canvas.create_oval(58,58,152,152,fill=self.colors["green"],outline=self.colors["green"]),self.qr_canvas.create_line(79,105,98,124,fill="#FFFFFF",width=7),self.qr_canvas.create_line(98,124,134,84,fill="#FFFFFF",width=7)]
        self.qr_status.configure(text="iPhone reconhecido",text_color=self.colors["green"])
        if hasattr(self,"connection_state"): self.connection_state.configure(text="● Conexão reconhecida",text_color=self.colors["green"])
        self.after(2400,self.restore_qr)

    def restore_qr(self):
        if not hasattr(self,"qr_canvas"): return
        try:
            for item in self.qr_complete_items: self.qr_canvas.delete(item)
            self.qr_complete_items=[]; self.qr_canvas.itemconfigure(self.qr_image_id,state="normal"); self.qr_canvas.itemconfigure(self.qr_arc,state="hidden"); self.qr_status.configure(text="Aguardando reconhecimento\ndo iPhone...",text_color=self.colors["blue"])
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
