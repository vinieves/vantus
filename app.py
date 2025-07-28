import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import bcrypt
import jwt
from functools import wraps
import secrets
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///vantus.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Configurações de sessão
app.config['SESSION_COOKIE_SECURE'] = False  # True em produção com HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    
    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()

# Modelo para logs de segurança
class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_security_event(action, ip_address, user_agent, success, user_id=None):
    log = SecurityLog(
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        user_id=user_id
    )
    db.session.add(log)
    db.session.commit()

def generate_secure_token():
    """Gera um token seguro para CSRF"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"Tentativa de login para usuário: {username}")  # Debug
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"Usuário não encontrado: {username}")  # Debug
            log_security_event('login_failed', request.remote_addr, request.user_agent.string, False)
            flash('Usuário ou senha incorretos.', 'error')
            return render_template('login.html')
        
        if user.is_locked():
            print(f"Usuário bloqueado: {username}")  # Debug
            flash('Conta temporariamente bloqueada. Tente novamente em 15 minutos.', 'error')
            log_security_event('login_attempt', request.remote_addr, request.user_agent.string, False)
            return render_template('login.html')
        
        if user.check_password(password):
            print(f"Senha correta para usuário: {username}")  # Debug
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            user.reset_failed_attempts()
            db.session.commit()
            
            print(f"Login bem-sucedido para usuário: {username}")  # Debug
            log_security_event('login_success', request.remote_addr, request.user_agent.string, True, user.id)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            print(f"Senha incorreta para usuário: {username}")  # Debug
            user.increment_failed_attempts()
            log_security_event('login_failed', request.remote_addr, request.user_agent.string, False)
            flash('Usuário ou senha incorretos.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validações
        if not username or not email or not password:
            flash('Todos os campos são obrigatórios.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('As senhas não coincidem.', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('A senha deve ter pelo menos 8 caracteres.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado.', 'error')
            return render_template('register.html')
        
        # Criar usuário
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        log_security_event('user_registration', request.remote_addr, request.user_agent.string, True, user.id)
        flash('Conta criada com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    log_security_event('logout', request.remote_addr, request.user_agent.string, True, current_user.id)
    logout_user()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Senha atual incorreta.', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('As novas senhas não coincidem.', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('A nova senha deve ter pelo menos 8 caracteres.', 'error')
            return render_template('change_password.html')
        
        current_user.set_password(new_password)
        db.session.commit()
        
        log_security_event('password_change', request.remote_addr, request.user_agent.string, True, current_user.id)
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=5000) 