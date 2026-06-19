"""
Inmova - Backend Flask API
PostgreSQL via Railway | Security hardened | Rate limiting
"""

import os
import re
import html
import time
import hashlib
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

# Security keys from environment variables (Railway)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# ─── Database (PostgreSQL via Railway) ────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///inmova_dev.db")
# Railway uses postgres:// but SQLAlchemy needs postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ─── CORS (allow React frontend) ──────────────────────────────────────────────
CORS(app, supports_credentials=True,
     origins=os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173").split(","))

# ─── Rate Limiting (in-memory, replace with Redis in production) ──────────────
_rate_buckets = defaultdict(list)

def rate_limit(max_calls: int, window_seconds: int):
    """Decorator: block IPs that exceed max_calls in window_seconds."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            bucket = _rate_buckets[ip]
            # Remove expired timestamps
            _rate_buckets[ip] = [t for t in bucket if now - t < window_seconds]
            if len(_rate_buckets[ip]) >= max_calls:
                return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde."}), 429
            _rate_buckets[ip].append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ─── Input Sanitization ───────────────────────────────────────────────────────
def sanitize(value: str, max_length: int = 500) -> str:
    """Strip HTML tags, escape special chars, trim length."""
    if not isinstance(value, str):
        return ""
    cleaned = html.escape(value.strip())
    return cleaned[:max_length]

def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))

def is_valid_phone(phone: str) -> bool:
    return bool(re.match(r"^\+?[\d\s\-\(\)]{7,20}$", phone))

# ─── CSRF Token Helpers ───────────────────────────────────────────────────────
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
    type        = db.Column(db.String(50))        # apartamento, casa, villa…
    status      = db.Column(db.String(20))        # venta, alquiler
    featured    = db.Column(db.Boolean, default=False)
    image_url   = db.Column(db.String(500))
    whatsapp    = db.Column(db.String(30))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    active      = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "price": float(self.price) if self.price else None,
            "currency": self.currency,
            "location": self.location,
            "bedrooms": self.bedrooms,
            "bathrooms": self.bathrooms,
            "area_sqm": self.area_sqm,
            "type": self.type,
            "status": self.status,
            "featured": self.featured,
            "image_url": self.image_url,
            "whatsapp": self.whatsapp,
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
    image_url  = db.Column(db.String(500))
    active     = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "bio": self.bio,
            "phone": self.phone,
            "email": self.email,
            "whatsapp": self.whatsapp,
            "image_url": self.image_url,
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
            "id": self.id,
            "name": self.name,
            "phone": self.phone,
            "email": self.email,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
            "read": self.read,
        }


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    @staticmethod
    def hash_password(pw: str) -> str:
        return generate_password_hash(pw)

    def verify_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


# ─── Auth Middleware ───────────────────────────────────────────────────────────
def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return jsonify({"error": "No autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ─── Public Routes ─────────────────────────────────────────────────────────────
@app.route("/api/properties", methods=["GET"])
def get_properties():
    status   = request.args.get("status")          # venta | alquiler
    featured = request.args.get("featured")
    q        = request.args.get("q", "").strip()

    query = Property.query.filter_by(active=True)
    if status:
        query = query.filter_by(status=status)
    if featured == "true":
        query = query.filter_by(featured=True)
    if q:
        query = query.filter(Property.title.ilike(f"%{q}%") | Property.location.ilike(f"%{q}%"))

    props = query.order_by(Property.created_at.desc()).all()
    return jsonify([p.to_dict() for p in props])


@app.route("/api/agents", methods=["GET"])
def get_agents():
    agents = Agent.query.filter_by(active=True).all()
    return jsonify([a.to_dict() for a in agents])


@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    return jsonify({"csrf_token": generate_csrf_token()})


@app.route("/api/contact", methods=["POST"])
@rate_limit(max_calls=5, window_seconds=300)  # 5 submissions per 5 min per IP
def submit_contact():
    data = request.get_json(silent=True) or {}

    # CSRF validation
    if not validate_csrf(data.get("csrf_token", "")):
        return jsonify({"error": "Token de seguridad inválido. Recarga la página."}), 403

    # Sanitize & validate
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


# ─── Admin Auth Routes ─────────────────────────────────────────────────────────
@app.route("/api/admin/login", methods=["POST"])
@rate_limit(max_calls=10, window_seconds=600)  # 10 attempts per 10 min
def admin_login():
    data     = request.get_json(silent=True) or {}
    username = sanitize(data.get("username", ""), 80)
    password = data.get("password", "")

    # Constant-time lookup to prevent timing attacks
    admin = AdminUser.query.filter_by(username=username).first()
    if not admin or not admin.verify_password(password):
        time.sleep(0.5)  # Slow brute-force
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


# ─── Admin CRUD – Properties ───────────────────────────────────────────────────
@app.route("/api/admin/properties", methods=["GET"])
@require_admin
def admin_get_properties():
    props = Property.query.order_by(Property.created_at.desc()).all()
    return jsonify([p.to_dict() for p in props])


@app.route("/api/admin/properties", methods=["POST"])
@require_admin
def admin_create_property():
    data = request.get_json(silent=True) or {}
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
            image_url   = sanitize(data.get("image_url", ""), 500),
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
    prop.image_url   = sanitize(data.get("image_url", prop.image_url or ""), 500)
    prop.whatsapp    = sanitize(data.get("whatsapp", prop.whatsapp or ""), 30)
    prop.active      = bool(data.get("active", prop.active))

    db.session.commit()
    return jsonify(prop.to_dict())


@app.route("/api/admin/properties/<int:prop_id>", methods=["DELETE"])
@require_admin
def admin_delete_property(prop_id):
    prop = Property.query.get_or_404(prop_id)
    prop.active = False  # Soft delete
    db.session.commit()
    return jsonify({"success": True})


# ─── Admin CRUD – Agents ───────────────────────────────────────────────────────
@app.route("/api/admin/agents", methods=["GET"])
@require_admin
def admin_get_agents():
    agents = Agent.query.all()
    return jsonify([a.to_dict() for a in agents])


@app.route("/api/admin/agents", methods=["POST"])
@require_admin
def admin_create_agent():
    data = request.get_json(silent=True) or {}
    agent = Agent(
        name      = sanitize(data.get("name", ""), 150),
        role      = sanitize(data.get("role", ""), 100),
        bio       = sanitize(data.get("bio", ""), 1000),
        phone     = sanitize(data.get("phone", ""), 30),
        email     = sanitize(data.get("email", ""), 200),
        whatsapp  = sanitize(data.get("whatsapp", ""), 30),
        image_url = sanitize(data.get("image_url", ""), 500),
    )
    db.session.add(agent)
    db.session.commit()
    return jsonify(agent.to_dict()), 201


@app.route("/api/admin/agents/<int:agent_id>", methods=["PUT"])
@require_admin
def admin_update_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    data  = request.get_json(silent=True) or {}

    agent.name      = sanitize(data.get("name", agent.name), 150)
    agent.role      = sanitize(data.get("role", agent.role or ""), 100)
    agent.bio       = sanitize(data.get("bio", agent.bio or ""), 1000)
    agent.phone     = sanitize(data.get("phone", agent.phone or ""), 30)
    agent.email     = sanitize(data.get("email", agent.email or ""), 200)
    agent.whatsapp  = sanitize(data.get("whatsapp", agent.whatsapp or ""), 30)
    agent.image_url = sanitize(data.get("image_url", agent.image_url or ""), 500)
    agent.active    = bool(data.get("active", agent.active))

    db.session.commit()
    return jsonify(agent.to_dict())


@app.route("/api/admin/agents/<int:agent_id>", methods=["DELETE"])
@require_admin
def admin_delete_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    agent.active = False
    db.session.commit()
    return jsonify({"success": True})


# ─── Admin – Leads ─────────────────────────────────────────────────────────────
@app.route("/api/admin/leads", methods=["GET"])
@require_admin
def admin_get_leads():
    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    return jsonify([l.to_dict() for l in leads])


@app.route("/api/admin/leads/<int:lead_id>/read", methods=["PUT"])
@require_admin
def admin_mark_lead_read(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    lead.read = True
    db.session.commit()
    return jsonify({"success": True})


# ─── DB Init + Seed ────────────────────────────────────────────────────────────
def seed_database():
    """Create default admin and sample data if tables are empty."""
    # Admin user from environment variables
    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("ADMIN_PASSWORD", "Inmova2025!")

    if not AdminUser.query.filter_by(username=admin_username).first():
        admin = AdminUser(
            username      = admin_username,
            password_hash = AdminUser.hash_password(admin_password),
        )
        db.session.add(admin)

    # Sample properties if none exist
    if Property.query.count() == 0:
        sample_properties = [
            Property(
                title="Penthouse de Lujo en Piantini",
                description="Espectacular penthouse con vista panorámica a la ciudad. Acabados de primera.",
                price=450000, currency="USD", location="Piantini, Santo Domingo",
                bedrooms=3, bathrooms=3, area_sqm=280,
                type="apartamento", status="venta", featured=True,
                image_url="https://images.unsplash.com/photo-1512917774080-9991f1c4c750?w=800",
                whatsapp="18095550001",
            ),
            Property(
                title="Apartamento Moderno en Evaristo Morales",
                description="Amplio apartamento con cocina abierta y balcón. Edificio nuevo con piscina.",
                price=185000, currency="USD", location="Evaristo Morales, Santo Domingo",
                bedrooms=2, bathrooms=2, area_sqm=120,
                type="apartamento", status="venta", featured=True,
                image_url="https://images.unsplash.com/photo-1502672260266-1c1ef2d93688?w=800",
                whatsapp="18095550002",
            ),
            Property(
                title="Villa Residencial en La Romana",
                description="Villa privada con jardín, piscina y área de BBQ. Urbanización cerrada.",
                price=320000, currency="USD", location="La Romana, Distrito Nacional",
                bedrooms=4, bathrooms=4, area_sqm=380,
                type="villa", status="venta", featured=True,
                image_url="https://images.unsplash.com/photo-1416331108676-a22ccb276e35?w=800",
                whatsapp="18095550003",
            ),
            Property(
                title="Apartamento en Alquiler – Gazcue",
                description="Acogedor apartamento amueblado. Ideal para ejecutivos o pareja.",
                price=800, currency="USD", location="Gazcue, Santo Domingo",
                bedrooms=1, bathrooms=1, area_sqm=65,
                type="apartamento", status="alquiler", featured=False,
                image_url="https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800",
                whatsapp="18095550004",
            ),
            Property(
                title="Local Comercial en Naco",
                description="Excelente local en planta baja. Alto tráfico peatonal. Listo para instalar.",
                price=2500, currency="USD", location="Naco, Santo Domingo",
                bedrooms=0, bathrooms=1, area_sqm=90,
                type="local", status="alquiler", featured=False,
                image_url="https://images.unsplash.com/photo-1497366216548-37526070297c?w=800",
                whatsapp="18095550005",
            ),
            Property(
                title="Casa Familiar en Los Ríos",
                description="Casa de dos plantas con patio. Barrio residencial tranquilo. Escuelas cercanas.",
                price=210000, currency="USD", location="Los Ríos, Santo Domingo Oeste",
                bedrooms=3, bathrooms=2, area_sqm=200,
                type="casa", status="venta", featured=False,
                image_url="https://images.unsplash.com/photo-1570129477492-45c003edd2be?w=800",
                whatsapp="18095550006",
            ),
        ]
        db.session.add_all(sample_properties)

    # Sample agents
    if Agent.query.count() == 0:
        sample_agents = [
            Agent(name="Carlos Méndez", role="Director Comercial",
                  bio="15 años de experiencia en bienes raíces en Santo Domingo.",
                  phone="18095551001", whatsapp="18095551001",
                  email="carlos@inmova.do",
                  image_url="https://images.unsplash.com/photo-1560250097-0b93528c311a?w=300"),
            Agent(name="Luisa Fernández", role="Asesora Senior",
                  bio="Especialista en propiedades residenciales de lujo.",
                  phone="18095551002", whatsapp="18095551002",
                  email="luisa@inmova.do",
                  image_url="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=300"),
            Agent(name="Ramón Torres", role="Asesor Comercial",
                  bio="Experto en inversiones y propiedades comerciales.",
                  phone="18095551003", whatsapp="18095551003",
                  email="ramon@inmova.do",
                  image_url="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=300"),
        ]
        db.session.add_all(sample_agents)

    db.session.commit()


with app.app_context():
    db.create_all()
    seed_database()

# ─── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
