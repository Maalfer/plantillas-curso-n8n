import os
import random
import string
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración básica
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Endpoint n8n
N8N_ENDPOINT = os.getenv(
    'N8N_ENDPOINT',
    'https://n8n.elpinguinodemario.es/webhook-test/0500b40b-c3b1-4160-b14e-28f36f93eab0'
)

# Inicializar DB
db = SQLAlchemy(app)


# Modelo de usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(10), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


# Generar un PIN de 6 dígitos
def generate_pin(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


# Enviar PIN al endpoint de n8n
def send_code_to_n8n(email: str, code: str) -> bool:
    payload = {
        "email": email,
        "code": code,
        "event": "user_registration_code"
    }
    try:
        resp = requests.post(N8N_ENDPOINT, json=payload, timeout=10)
        return 200 <= resp.status_code < 300
    except requests.RequestException:
        return False


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not email or not password:
            flash('Email y contraseña son obligatorios.', 'error')
            return render_template('register.html')
        if password != confirm:
            flash('Las contraseñas no coinciden.', 'error')
            return render_template('register.html')

        existing = User.query.filter_by(email=email).first()
        if existing:
            if existing.is_verified:
                flash('Este email ya está registrado y verificado. Inicia sesión.', 'info')
                return redirect(url_for('login'))
            else:
                # Usuario pendiente: regenerar PIN y re-enviar
                code = generate_pin()
                existing.verification_code = code
                db.session.commit()
                ok = send_code_to_n8n(email, code)
                if ok:
                    flash('Hemos reenviado tu PIN de verificación. Revisa tu canal en n8n.', 'success')
                else:
                    flash('No se pudo notificar a n8n. Intenta de nuevo.', 'warning')
                return redirect(url_for('verify', email=email))

        # Crear nuevo usuario pendiente
        user = User(email=email, is_verified=False)
        user.set_password(password)
        code = generate_pin()
        user.verification_code = code
        db.session.add(user)
        db.session.commit()

        ok = send_code_to_n8n(email, code)
        if ok:
            flash('Registro iniciado. Te enviamos el PIN de verificación vía n8n.', 'success')
        else:
            flash('Registro iniciado, pero no se pudo notificar a n8n.', 'warning')

        return redirect(url_for('verify', email=email))

    return render_template('register.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        code = request.form.get('code', '').strip()

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No existe una cuenta con ese email. Regístrate primero.', 'error')
            return render_template('verify.html')
        if user.is_verified:
            flash('Tu cuenta ya está verificada. Puedes iniciar sesión.', 'info')
            return redirect(url_for('login'))

        if user.verification_code and code == user.verification_code:
            user.is_verified = True
            user.verification_code = None
            db.session.commit()
            flash('¡Cuenta verificada! Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        else:
            flash('PIN incorrecto. Revisa el código recibido.', 'error')
            return render_template('verify.html', email=email)

    # GET
    email = request.args.get('email', '')
    return render_template('verify.html', email=email)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Credenciales inválidas.', 'error')
            return render_template('login.html')
        if not user.is_verified:
            flash('Tu cuenta aún no está verificada. Introduce el PIN.', 'warning')
            return redirect(url_for('verify', email=email))

        session['user_id'] = user.id
        session['user_email'] = user.email
        flash('Has iniciado sesión.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Inicia sesión primero.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session.get('user_email'))


# Crear tablas al arrancar (compatible con Flask 3.1+ que no tiene before_first_request)
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
