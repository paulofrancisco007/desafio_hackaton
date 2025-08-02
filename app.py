import os
import hashlib
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import numpy as np
from PIL import Image
import piexif
from PyPDF2 import PdfReader

# ===== Configuração do Flask =====
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config.update(
    UPLOAD_FOLDER='uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1))
    
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ===== Configuração do Banco de Dados =====
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'database': os.environ.get('DB_NAME', 'govdocs')
}

# ===== Decorators =====
# ===== Decorators =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Você precisa estar logado.", 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Acesso restrito a administradores.", 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ===== Funções do Banco de Dados =====
def init_database():
    """Inicializa o banco de dados com todas as tabelas necessárias"""
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'])
            
        cursor = conn.cursor()
        
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        # Tabela de usuários
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabela de documentos
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                hash VARCHAR(64) NOT NULL,
                user_id INT NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata JSON,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            )
        """)
        
        # Tabela de auditoria
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auditoria (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                acao VARCHAR(50) NOT NULL,
                descricao TEXT,
                data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            )
        """)
        
        # Cria usuário admin padrão se não existir
        cursor.execute("SELECT id FROM usuarios WHERE username = 'admin'")
        if not cursor.fetchone():
            password_hash = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO usuarios (username, password_hash, is_admin)
                VALUES (%s, %s, TRUE)
            """, ('admin', password_hash))
        
        conn.commit()
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"Erro ao inicializar banco de dados: {err}")
        raise

init_database()

def get_db():
    """Retorna uma conexão com o banco de dados"""
    return mysql.connector.connect(**DB_CONFIG)

def log_audit(user_id, action, description):
    """Registra ação na auditoria"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auditoria (user_id, acao, descricao)
            VALUES (%s, %s, %s)
        """, (user_id, action, description))
        conn.commit()
    except Exception as e:
        print(f"Erro ao registrar auditoria: {e}")
    finally:
        if conn.is_connected():
            conn.close()

# ===== Funções Auxiliares =====
def calculate_hash(filepath):
    """Calcula hash SHA-256 de um arquivo"""
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def validate_file(file):
    """Valida tipo e conteúdo do arquivo"""
    filename = file.filename.lower()
    
    if not filename.endswith(('.pdf', '.jpg', '.jpeg', '.png')):
        return False, "Tipo de arquivo não suportado"
    
    if filename.endswith('.pdf'):
        try:
            file.seek(0)
            reader = PdfReader(file)
            if len(reader.pages) == 0:
                return False, "PDF inválido"
        except:
            return False, "PDF corrompido"
    
    return True, "Arquivo válido"

def extract_metadata(filepath):
    """Extrai metadados de arquivos"""
    try:
        if filepath.lower().endswith(('.png', '.jpg', '.jpeg')):
            img = Image.open(filepath)
            exif_data = img.info.get('exif')
            if exif_data:
                exif_dict = piexif.load(exif_data)
                return {
                    'camera': exif_dict.get('0th', {}).get(piexif.ImageIFD.Model),
                    'data_criacao': exif_dict.get('Exif', {}).get(piexif.ExifIFD.DateTimeOriginal),
                    'software': exif_dict.get('0th', {}).get(piexif.ImageIFD.Software)
                }
        return {}
    except Exception as e:
        print(f"Erro ao extrair metadados: {e}")
        return {}

def detect_tampering(original_path, uploaded_path):
    """Detecta adulterações em imagens"""
    try:
        original = cv2.imread(original_path, 0)
        uploaded = cv2.imread(uploaded_path, 0)
        
        if original is None or uploaded is None:
            return False
            
        if original.shape != uploaded.shape:
            return True
            
        diff = cv2.absdiff(original, uploaded)
        threshold = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)[1]
        changed_pixels = np.sum(threshold) / 255
        
        return changed_pixels > (original.size * 0.01)
    except Exception as e:
        print(f"Erro na detecção de adulteração: {e}")
        return False

# ===== Context Processors =====
@app.context_processor
def inject_globals():
    return {
        'current_year': datetime.now().year,
        'app_name': 'GovDocsRN'
    }

# ===== Rotas Principais =====
@app.route('/')
def index():
    if 'user' in session:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT d.id, d.original_filename, d.upload_date 
            FROM documentos d
            WHERE d.user_id = %s 
            ORDER BY d.upload_date DESC LIMIT 5
        """, (session['user_id'],))
        recent_docs = cursor.fetchall()
        conn.close()
        return render_template('index.html', user=session['user'], docs=recent_docs)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if len(username) < 4 or len(password) < 6:
            flash('Username deve ter pelo menos 4 caracteres e senha 6 caracteres', 'danger')
            return redirect(url_for('register'))

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Verifica se usuário já existe
            cursor.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Usuário já existe', 'danger')
                return redirect(url_for('register'))
            
            # Cria novo usuário
            password_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO usuarios (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            conn.commit()
            
            # Configura a sessão
            session['user'] = username
            session['user_id'] = cursor.lastrowid
            
            log_audit(session['user_id'], 'REGISTER', f'Novo usuário registrado: {username}')
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            conn.rollback()
            flash(f'Erro no cadastro: {str(e)}', 'danger')
            return redirect(url_for('register'))
            
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, password_hash, is_admin FROM usuarios WHERE username = %s", 
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user'] = user['username']
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            
            log_audit(user['id'], 'LOGIN', 'Login realizado')
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha incorretos', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        log_audit(session['user_id'], 'LOGOUT', 'Logout realizado')
        session.clear()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('Nenhum arquivo enviado', 'danger')
            return redirect(url_for('upload'))
            
        file = request.files['document']
        if file.filename == '':
            flash('Nenhum arquivo selecionado', 'danger')
            return redirect(url_for('upload'))
            
        # Validação do arquivo
        is_valid, message = validate_file(file)
        if not is_valid:
            flash(f'Arquivo inválido: {message}', 'danger')
            return redirect(url_for('upload'))
        
        filename = secure_filename(file.filename)
        original_filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Processamento do documento
        file_hash = calculate_hash(filepath)
        metadata = extract_metadata(filepath)
        
        # Registrar no banco de dados
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO documentos 
                (filename, original_filename, hash, user_id, metadata) 
                VALUES (%s, %s, %s, %s, %s)
            """, (filename, original_filename, file_hash, session['user_id'], json.dumps(metadata)))
            
            conn.commit()
            
            log_audit(
                session['user_id'], 
                'UPLOAD', 
                f"Documento enviado: {original_filename} (Hash: {file_hash})"
            )
            
            flash('Documento enviado com sucesso!', 'success')
            return redirect(url_for('document_detail', doc_id=cursor.lastrowid))
            
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao enviar documento: {str(e)}', 'danger')
            return redirect(url_for('upload'))
            
        finally:
            conn.close()
    
    return render_template('upload.html')

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('Nenhum arquivo selecionado', 'danger')
            return redirect(url_for('verify'))
            
        file = request.files['document']
        if file.filename == '':
            flash('Nenhum arquivo selecionado', 'danger')
            return redirect(url_for('verify'))
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"verify_{filename}")
        file.save(filepath)
        
        file_hash = calculate_hash(filepath)
        
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT d.hash, d.original_filename, u.username 
            FROM documentos d
            JOIN usuarios u ON d.user_id = u.id
            WHERE d.filename = %s
        """, (filename,))
        
        original = cursor.fetchone()
        conn.close()
        
        is_valid = bool(original and original['hash'] == file_hash)
        
        # Limpa o arquivo temporário
        os.remove(filepath)
        
        return render_template('verify_result.html', 
                           filename=original['original_filename'] if original else filename,
                           is_valid=is_valid,
                           original_hash=original['hash'] if original else None,
                           current_hash=file_hash,
                           uploaded_by=original['username'] if original else None)
    
    return render_template('verify.html')

@app.route('/document/<int:doc_id>')
@login_required
def document_detail(doc_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT d.*, u.username 
        FROM documentos d
        JOIN usuarios u ON d.user_id = u.id
        WHERE d.id = %s
    """, (doc_id,))
    
    document = cursor.fetchone()
    conn.close()
    
    if not document:
        flash('Documento não encontrado', 'danger')
        return redirect(url_for('index'))
    
    # Converter metadata de string JSON para dicionário
    if document.get('metadata'):
        try:
            document['metadata'] = json.loads(document['metadata'])
        except (json.JSONDecodeError, TypeError):
            document['metadata'] = {'Erro': 'Formato inválido'}
    else:
        document['metadata'] = {}
    
    # Verifica permissão
    if not session.get('is_admin') and document['user_id'] != session['user_id']:
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('index'))
    
    return render_template('document_detail.html', document=document)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Estatísticas
    cursor.execute("""
        SELECT 
            COUNT(*) as total_docs,
            COUNT(DISTINCT user_id) as total_users,
            MAX(upload_date) as last_upload
        FROM documentos
    """)
    stats = cursor.fetchone()
    
    # Últimos documentos
    cursor.execute("""
        SELECT d.id, d.original_filename, u.username, d.upload_date 
        FROM documentos d
        JOIN usuarios u ON d.user_id = u.id
        ORDER BY d.upload_date DESC LIMIT 10
    """)
    recent_docs = cursor.fetchall()
    
    # Atividades recentes
    cursor.execute("""
        SELECT a.acao, a.descricao, a.data, u.username
        FROM auditoria a
        JOIN usuarios u ON a.user_id = u.id
        ORDER BY a.data DESC LIMIT 10
    """)
    activities = cursor.fetchall()
    
    conn.close()
    return render_template('admin.html', stats=stats, docs=recent_docs, activities=activities)

# ===== Rotas de API =====
@app.route('/api/documents')
@login_required
def api_documents():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    if session.get('is_admin'):
        cursor.execute("""
            SELECT d.id, d.original_filename, d.upload_date, u.username
            FROM documentos d
            JOIN usuarios u ON d.user_id = u.id
            ORDER BY d.upload_date DESC
        """)
    else:
        cursor.execute("""
            SELECT d.id, d.original_filename, d.upload_date
            FROM documentos d
            WHERE d.user_id = %s
            ORDER BY d.upload_date DESC
        """, (session['user_id'],))
    
    documents = cursor.fetchall()
    conn.close()
    return jsonify(documents)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)