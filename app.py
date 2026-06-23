"""
Inmova — Backend Flask API v4
Cambios v4:
- Endpoint /api/admin/upload-image: recibe base64, valida tipo/tamaño, devuelve data-URL
- Modelo SiteImage: almacena imágenes de la página (hero1/2/3, about, showcase)
- GET/PUT /api/site-images: público (lectura) y admin (escritura)
- Buscador backend más flexible: búsqueda fuzzy por palabras sueltas
"""

import os
import re
import html
import time
import base64
import secrets
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"]   = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# Image upload limit: 5 MB per image
MAX_IMAGE_BYTES = 5 * 1024 * 1024
ALLOWED_MIME    = {"image/jpeg", "image/png", "image/webp", "image/gif"}

# ─── Database ────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///inmova_dev.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"]        = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ─── CORS ─────────────────────────────────────────────────────────────────────
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
CORS(app,
     supports_credentials=True,
     origins=[o.strip() for o in allowed_origins],
     allow_headers=["Content-Type"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# ─── Rate Limiting ────────────────────────────────────────────────────────────
_rate_buckets = defaultdict(list)

def rate_limit(max_calls: int, window_seconds: int):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            _rate_buckets[ip] = [t for t in _rate_buckets[ip] if now - t < window_seconds]
            if len(_rate_buckets[ip]) >= max_calls:
                return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde."}), 429
            _rate_buckets[ip].append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ─── Helpers ──────────────────────────────────────────────────────────────────
def sanitize(value: str, max_length: int = 500) -> str:
    if not isinstance(value, str):
        return ""
    return html.escape(value.strip())[:max_length]

def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

def is_valid_phone(phone: str) -> bool:
    return bool(re.match(r"^\+?[\d\s\-\(\)]{7,20}$", phone))

def generate_csrf_token():
    token = secrets.token_hex(32)
    session["csrf_token"] = token
    return token

def validate_csrf(token: str) -> bool:
    return token == session.get("csrf_token")

# ─── Models ───────────────────────────────────────────────────────────────────
class Property(db.Model):
    __tablename__ = "properties"

    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price       = db.Column(db.Numeric(14, 2))
    currency    = db.Column(db.String(5), default="USD")
    location    = db.Column(db.String(300))
    bedrooms    = db.Column(db.Integer)
    bathrooms   = db.Column(db.Integer)
    area_sqm    = db.Column(db.Integer)
    type        = db.Column(db.String(50))
    status      = db.Column(db.String(20))
    featured    = db.Column(db.Boolean, default=False)
    image_url   = db.Column(db.Text)        # TEXT to support base64 data-URLs
    whatsapp    = db.Column(db.String(30))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    active      = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title,
            "description": self.description,
            "price": float(self.price) if self.price else None,
            "currency": self.currency, "location": self.location,
            "bedrooms": self.bedrooms, "bathrooms": self.bathrooms,
            "area_sqm": self.area_sqm, "type": self.type,
            "status": self.status, "featured": self.featured,
            "image_url": self.image_url, "whatsapp": self.whatsapp,
            "created_at": self.created_at.isoformat(),
        }


class Agent(db.Model):
    __tablename__ = "agents"

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(150), nullable=False)
    role       = db.Column(db.String(100))
    bio        = db.Column(db.Text)
    phone      = db.Column(db.String(30))
    email      = db.Column(db.String(200))
    whatsapp   = db.Column(db.String(30))
    image_url  = db.Column(db.Text)         # TEXT for base64
    active     = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "role": self.role,
            "bio": self.bio, "phone": self.phone, "email": self.email,
            "whatsapp": self.whatsapp, "image_url": self.image_url,
        }


class Lead(db.Model):
    __tablename__ = "leads"

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(150), nullable=False)
    phone      = db.Column(db.String(30), nullable=False)
    email      = db.Column(db.String(200))
    message    = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read       = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "phone": self.phone,
            "email": self.email, "message": self.message,
            "created_at": self.created_at.isoformat(), "read": self.read,
        }


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    @staticmethod
    def hash_password(pw): return generate_password_hash(pw)
    def verify_password(self, pw): return check_password_hash(self.password_hash, pw)


class SiteImage(db.Model):
    """Stores page-level images: hero1/hero2/hero3/about/showcase.
    key is a fixed slug; image_url holds the data-URL or external URL."""
    __tablename__ = "site_images"

    id         = db.Column(db.Integer, primary_key=True)
    key        = db.Column(db.String(50), unique=True, nullable=False)
    image_url  = db.Column(db.Text)
    label      = db.Column(db.String(100))  # Human-readable name
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "key": self.key,
            "label": self.label,
            "image_url": self.image_url,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ─── Auth middleware ───────────────────────────────────────────────────────────
def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return jsonify({"error": "No autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ─── Image upload helper ──────────────────────────────────────────────────────
def validate_and_store_image(data_url: str) -> tuple[bool, str]:
    """
    Validate a base64 data-URL.
    Returns (ok, error_message). If ok, error_message is empty.
    Allowed: JPEG, PNG, WebP, GIF. Max 5 MB.
    """
    if not data_url:
        return True, ""  # Empty is OK (no image change)

    # External URLs are allowed as-is (for backwards compat)
    if data_url.startswith("http://") or data_url.startswith("https://"):
        return True, ""

    # Must be a data URL
    if not data_url.startswith("data:"):
        return False, "Formato de imagen no válido."

    # Extract MIME type
    try:
        header, b64data = data_url.split(",", 1)
        mime = header.split(":")[1].split(";")[0].lower()
    except (ValueError, IndexError):
        return False, "Formato de imagen no válido."

    if mime not in ALLOWED_MIME:
        return False, f"Tipo de imagen no permitido ({mime}). Usa JPG, PNG o WebP."

    # Check size (base64 is ~33% larger than binary)
    try:
        raw_bytes = base64.b64decode(b64data)
    except Exception:
        return False, "No se pudo decodificar la imagen."

    if len(raw_bytes) > MAX_IMAGE_BYTES:
        size_mb = len(raw_bytes) / (1024 * 1024)
        return False, f"La imagen es demasiado grande ({size_mb:.1f} MB). Máximo 5 MB."

    return True, ""


# ─── Public Routes ─────────────────────────────────────────────────────────────

@app.route("/api/properties", methods=["GET"])
def get_properties():
    status   = request.args.get("status")
    featured = request.args.get("featured")
    q        = request.args.get("q", "").strip()

    query = Property.query.filter_by(active=True)
    if status:
        query = query.filter_by(status=status)
    if featured == "true":
        query = query.filter_by(featured=True)

    # Flexible search: each word in the query must appear somewhere
    if q:
        words = q.lower().split()
        for word in words:
            pattern = f"%{word}%"
            query = query.filter(
                db.or_(
                    Property.title.ilike(pattern),
                    Property.location.ilike(pattern),
                    Property.type.ilike(pattern),
                    Property.description.ilike(pattern),
                )
            )

    props = query.order_by(Property.created_at.desc()).all()
    return jsonify([p.to_dict() for p in props])


@app.route("/api/agents", methods=["GET"])
def get_agents():
    return jsonify([a.to_dict() for a in Agent.query.filter_by(active=True).all()])


@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    return jsonify({"csrf_token": generate_csrf_token()})


# Public: read site images (frontend uses these for hero/about/showcase)
@app.route("/api/site-images", methods=["GET"])
def get_site_images():
    images = SiteImage.query.all()
    return jsonify({img.key: img.to_dict() for img in images})


@app.route("/api/contact", methods=["POST"])
@rate_limit(max_calls=5, window_seconds=300)
def submit_contact():
    data    = request.get_json(silent=True) or {}

    if not validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Token de seguridad inválido. Recarga la página."}), 403

    name    = sanitize(data.get("name", ""), 100)
    phone   = sanitize(data.get("phone", ""), 30)
    email   = sanitize(data.get("email", ""), 150)
    message = sanitize(data.get("message", ""), 1000)

    if not name or len(name) < 2:
        return jsonify({"error": "Nombre inválido."}), 400
    if not phone or not is_valid_phone(phone):
        return jsonify({"error": "Teléfono inválido."}), 400
    if email and not is_valid_email(email):
        return jsonify({"error": "Correo inválido."}), 400

    lead = Lead(name=name, phone=phone, email=email, message=message)
    db.session.add(lead)
    db.session.commit()
    return jsonify({"success": True, "message": "Mensaje recibido. Te contactaremos pronto."}), 201


# ─── Admin Auth ────────────────────────────────────────────────────────────────

@app.route("/api/admin/login", methods=["POST"])
@rate_limit(max_calls=10, window_seconds=600)
def admin_login():
    data     = request.get_json(silent=True) or {}
    username = sanitize(data.get("username", ""), 80)
    password = data.get("password", "")

    admin = AdminUser.query.filter_by(username=username).first()
    if not admin or not admin.verify_password(password):
        time.sleep(0.5)
        return jsonify({"error": "Credenciales incorrectas."}), 401

    session.permanent = True
    session["admin_logged_in"] = True
    session["admin_id"] = admin.id
    return jsonify({"success": True})


@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/admin/check", methods=["GET"])
def admin_check():
    return jsonify({"authenticated": bool(session.get("admin_logged_in"))})


# ─── Image Upload (admin only) ────────────────────────────────────────────────

@app.route("/api/admin/upload-image", methods=["POST"])
@require_admin
@rate_limit(max_calls=30, window_seconds=60)
def admin_upload_image():
    """
    Receive a base64 data-URL, validate it, and return it back.
    The caller stores the returned URL in the relevant model field.
    This endpoint is stateless — it just validates and echoes.
    """
    data      = request.get_json(silent=True) or {}
    data_url  = data.get("image", "")

    ok, err = validate_and_store_image(data_url)
    if not ok:
        return jsonify({"error": err}), 400

    return jsonify({"url": data_url}), 200


# ─── Admin: Site Images ───────────────────────────────────────────────────────

@app.route("/api/admin/site-images", methods=["GET"])
@require_admin
def admin_get_site_images():
    images = SiteImage.query.all()
    return jsonify({img.key: img.to_dict() for img in images})


@app.route("/api/admin/site-images/<string:key>", methods=["PUT"])
@require_admin
def admin_update_site_image(key):
    # Only allow known keys
    ALLOWED_KEYS = {"hero1", "hero2", "hero3", "about", "showcase"}
    if key not in ALLOWED_KEYS:
        return jsonify({"error": "Clave de imagen no válida."}), 400

    data      = request.get_json(silent=True) or {}
    image_url = data.get("image_url", "")

    ok, err = validate_and_store_image(image_url)
    if not ok:
        return jsonify({"error": err}), 400

    img = SiteImage.query.filter_by(key=key).first()
    if img:
        img.image_url  = image_url
        img.updated_at = datetime.utcnow()
    else:
        img = SiteImage(key=key, image_url=image_url,
                        label=data.get("label", key))
        db.session.add(img)

    db.session.commit()
    return jsonify(img.to_dict())


# ─── Admin: Properties ────────────────────────────────────────────────────────

@app.route("/api/admin/properties", methods=["GET"])
@require_admin
def admin_get_properties():
    return jsonify([p.to_dict() for p in
                    Property.query.order_by(Property.created_at.desc()).all()])


@app.route("/api/admin/properties", methods=["POST"])
@require_admin
def admin_create_property():
    data = request.get_json(silent=True) or {}
    image_url = data.get("image_url", "")
    ok, err = validate_and_store_image(image_url)
    if not ok:
        return jsonify({"error": err}), 400
    try:
        prop = Property(
            title       = sanitize(data.get("title", ""), 200),
            description = sanitize(data.get("description", ""), 2000),
            price       = float(data.get("price", 0)) or None,
            currency    = sanitize(data.get("currency", "USD"), 5),
            location    = sanitize(data.get("location", ""), 300),
            bedrooms    = int(data.get("bedrooms", 0)),
            bathrooms   = int(data.get("bathrooms", 0)),
            area_sqm    = int(data.get("area_sqm", 0)),
            type        = sanitize(data.get("type", "apartamento"), 50),
            status      = sanitize(data.get("status", "venta"), 20),
            featured    = bool(data.get("featured", False)),
            image_url   = image_url,
            whatsapp    = sanitize(data.get("whatsapp", ""), 30),
            active      = True,
        )
        db.session.add(prop)
        db.session.commit()
        return jsonify(prop.to_dict()), 201
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Datos inválidos: {str(e)}"}), 400


@app.route("/api/admin/properties/<int:prop_id>", methods=["PUT"])
@require_admin
def admin_update_property(prop_id):
    prop = Property.query.get_or_404(prop_id)
    data = request.get_json(silent=True) or {}

    if "image_url" in data:
        ok, err = validate_and_store_image(data["image_url"])
        if not ok:
            return jsonify({"error": err}), 400
        prop.image_url = data["image_url"]

    prop.title       = sanitize(data.get("title", prop.title), 200)
    prop.description = sanitize(data.get("description", prop.description or ""), 2000)
    prop.price       = float(data["price"]) if "price" in data else prop.price
    prop.currency    = sanitize(data.get("currency", prop.currency), 5)
    prop.location    = sanitize(data.get("location", prop.location or ""), 300)
    prop.bedrooms    = int(data.get("bedrooms", prop.bedrooms or 0))
    prop.bathrooms   = int(data.get("bathrooms", prop.bathrooms or 0))
    prop.area_sqm    = int(data.get("area_sqm", prop.area_sqm or 0))
    prop.type        = sanitize(data.get("type", prop.type or ""), 50)
    prop.status      = sanitize(data.get("status", prop.status or ""), 20)
    prop.featured    = bool(data.get("featured", prop.featured))
    prop.whatsapp    = sanitize(data.get("whatsapp", prop.whatsapp or ""), 30)
    prop.active      = bool(data.get("active", prop.active))

    db.session.commit()
    return jsonify(prop.to_dict())


@app.route("/api/admin/properties/<int:prop_id>", methods=["DELETE"])
@require_admin
def admin_delete_property(prop_id):
    prop = Property.query.get_or_404(prop_id)
    prop.active = False
    db.session.commit()
    return jsonify({"success": True})


# ─── Admin: Agents ────────────────────────────────────────────────────────────

@app.route("/api/admin/agents", methods=["GET"])
@require_admin
def admin_get_agents():
    return jsonify([a.to_dict() for a in Agent.query.all()])


@app.route("/api/admin/agents", methods=["POST"])
@require_admin
def admin_create_agent():
    data = request.get_json(silent=True) or {}
    image_url = data.get("image_url", "")
    ok, err = validate_and_store_image(image_url)
    if not ok:
        return jsonify({"error": err}), 400

    agent = Agent(
        name      = sanitize(data.get("name", ""), 150),
        role      = sanitize(data.get("role", ""), 100),
        bio       = sanitize(data.get("bio", ""), 1000),
        phone     = sanitize(data.get("phone", ""), 30),
        email     = sanitize(data.get("email", ""), 200),
        whatsapp  = sanitize(data.get("whatsapp", ""), 30),
        image_url = image_url,
    )
    db.session.add(agent)
    db.session.commit()
    return jsonify(agent.to_dict()), 201


@app.route("/api/admin/agents/<int:agent_id>", methods=["PUT"])
@require_admin
def admin_update_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    data  = request.get_json(silent=True) or {}

    if "image_url" in data:
        ok, err = validate_and_store_image(data["image_url"])
        if not ok:
            return jsonify({"error": err}), 400
        agent.image_url = data["image_url"]

    agent.name     = sanitize(data.get("name", agent.name), 150)
    agent.role     = sanitize(data.get("role", agent.role or ""), 100)
    agent.bio      = sanitize(data.get("bio", agent.bio or ""), 1000)
    agent.phone    = sanitize(data.get("phone", agent.phone or ""), 30)
    agent.email    = sanitize(data.get("email", agent.email or ""), 200)
    agent.whatsapp = sanitize(data.get("whatsapp", agent.whatsapp or ""), 30)
    agent.active   = bool(data.get("active", agent.active))

    db.session.commit()
    return jsonify(agent.to_dict())


@app.route("/api/admin/agents/<int:agent_id>", methods=["DELETE"])
@require_admin
def admin_delete_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    agent.active = False
    db.session.commit()
    return jsonify({"success": True})


# ─── Admin: Leads ─────────────────────────────────────────────────────────────

@app.route("/api/admin/leads", methods=["GET"])
@require_admin
def admin_get_leads():
    return jsonify([l.to_dict() for l in
                    Lead.query.order_by(Lead.created_at.desc()).all()])


@app.route("/api/admin/leads/<int:lead_id>/read", methods=["PUT"])
@require_admin
def admin_mark_lead_read(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    lead.read = True
    db.session.commit()
    return jsonify({"success": True})


# ─── DB Init + Seed ────────────────────────────────────────────────────────────
def seed_database():
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Inmova2025!")

    if not AdminUser.query.filter_by(username=admin_username).first():
        db.session.add(AdminUser(
            username      = admin_username,
            password_hash = AdminUser.hash_password(admin_password),
        ))

    if Property.query.count() == 0:
        db.session.add_all([
            Property(title="Penthouse de Lujo en Piantini",
                description="Espectacular penthouse con vista panorámica. Acabados de primera calidad.",
                price=450000, currency="USD", location="Piantini, Santo Domingo",
                bedrooms=3, bathrooms=3, area_sqm=280, type="apartamento",
                status="venta", featured=True,
                image_url="https://images.unsplash.com/photo-1512917774080-9991f1c4c750?w=800",
                whatsapp="18095550001"),
            Property(title="Apartamento Moderno en Evaristo Morales",
                description="Amplio apartamento con cocina abierta y balcón. Edificio nuevo con piscina.",
                price=185000, currency="USD", location="Evaristo Morales, Santo Domingo",
                bedrooms=2, bathrooms=2, area_sqm=120, type="apartamento",
                status="venta", featured=True,
                image_url="https://images.unsplash.com/photo-1502672260266-1c1ef2d93688?w=800",
                whatsapp="18095550002"),
            Property(title="Villa Residencial en La Romana",
                description="Villa privada con jardín, piscina y área de BBQ. Urbanización cerrada.",
                price=320000, currency="USD", location="La Romana, Distrito Nacional",
                bedrooms=4, bathrooms=4, area_sqm=380, type="villa",
                status="venta", featured=True,
                image_url="https://images.unsplash.com/photo-1416331108676-a22ccb276e35?w=800",
                whatsapp="18095550003"),
            Property(title="Apartamento Amueblado en Gazcue",
                description="Acogedor apartamento amueblado, ideal para ejecutivos.",
                price=800, currency="USD", location="Gazcue, Santo Domingo",
                bedrooms=1, bathrooms=1, area_sqm=65, type="apartamento",
                status="alquiler", featured=False,
                image_url="https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800",
                whatsapp="18095550004"),
            Property(title="Local Comercial en Naco",
                description="Excelente local en planta baja. Alto tráfico peatonal.",
                price=2500, currency="USD", location="Naco, Santo Domingo",
                bedrooms=0, bathrooms=1, area_sqm=90, type="local",
                status="alquiler", featured=False,
                image_url="https://images.unsplash.com/photo-1497366216548-37526070297c?w=800",
                whatsapp="18095550005"),
            Property(title="Casa Familiar en Los Ríos",
                description="Casa de dos plantas con patio. Barrio residencial tranquilo.",
                price=210000, currency="USD", location="Los Ríos, Santo Domingo Oeste",
                bedrooms=3, bathrooms=2, area_sqm=200, type="casa",
                status="venta", featured=False,
                image_url="https://images.unsplash.com/photo-1570129477492-45c003edd2be?w=800",
                whatsapp="18095550006"),
        ])

    if Agent.query.count() == 0:
        db.session.add_all([
            Agent(name="Carlos Méndez", role="Director Comercial",
                bio="15 años de experiencia en bienes raíces en Santo Domingo.",
                phone="18095551001", whatsapp="18095551001", email="carlos@inmova.do",
                image_url="https://images.unsplash.com/photo-1560250097-0b93528c311a?w=300"),
            Agent(name="Luisa Fernández", role="Asesora Senior",
                bio="Especialista en propiedades residenciales de lujo.",
                phone="18095551002", whatsapp="18095551002", email="luisa@inmova.do",
                image_url="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=300"),
            Agent(name="Ramón Torres", role="Asesor Comercial",
                bio="Experto en inversiones y propiedades comerciales.",
                phone="18095551003", whatsapp="18095551003", email="ramon@inmova.do",
                image_url="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=300"),
        ])

    # Seed default site images (local files as fallback)
    SITE_IMAGE_DEFAULTS = [
        ("hero1",    "/hero-city.jpg",       "Hero — Imagen 1"),
        ("hero2",    "/hero-city2.jpg",      "Hero — Imagen 2"),
        ("hero3",    "/hero-city3.jpg",      "Hero — Imagen 3"),
        ("about",    "/interior-living.jpg", "Sección Nosotros"),
        ("showcase", "/interior-dining.png", "Sección Exclusividad"),
    ]
    for key, url, label in SITE_IMAGE_DEFAULTS:
        if not SiteImage.query.filter_by(key=key).first():
            db.session.add(SiteImage(key=key, image_url=url, label=label))

    db.session.commit()


with app.app_context():
    db.create_all()
    seed_database()

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
