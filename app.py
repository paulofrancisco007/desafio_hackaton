from flask import Flask, render_template, request, redirect, url_for, session, flash
import os, hashlib
import mysql.connector
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'chave-secreta-flask'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===== Configuração do MySQL =====
initial_db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': ''
}

def init_database():
    try:
        # Conectar sem especificar o banco de dados
        conn = mysql.connector.connect(**initial_db_config)
        cursor = conn.cursor()
        
        # Criar o banco de dados se não existir
        cursor.execute("CREATE DATABASE IF NOT EXISTS govdocs")
        
        # Usar o banco de dados
        cursor.execute("USE govdocs")
        
        # Criar tabelas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                hash VARCHAR(64) NOT NULL,
                user_id INT NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            )
        """)
        
        conn.commit()
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"Erro ao inicializar banco de dados: {err}")

# Chame esta função antes de iniciar o aplicativo
init_database()

def get_db():
    db_config = {
        'host': 'localhost',
        'user': 'root',
        'password': '',
        'database': 'govdocs'  # Adicione esta linha
    }
    return mysql.connector.connect(**db_config)


# ===== Funções auxiliares =====

def calculate_hash(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def get_user_by_username(username):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# ===== Rotas =====

@app.route('/')
def index():
    return render_template('index.html', user=session.get("user"))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        if get_user_by_username(username):
            flash("Usuário já existe.")
            return redirect(url_for('register'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO usuarios (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        conn.commit()
        conn.close()
        flash("Cadastro realizado com sucesso.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            session['user'] = username
            session['user_id'] = user['id']
            flash("Login realizado com sucesso.")
            return redirect(url_for('index'))
        else:
            flash("Credenciais inválidas.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sessão encerrada.")
    return redirect(url_for('index'))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user' not in session:
            flash("Você precisa estar logado.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['document']
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            file_hash = calculate_hash(filepath)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO documentos (filename, hash, user_id) VALUES (%s, %s, %s)", (filename, file_hash, session['user_id']))
            conn.commit()
            conn.close()

            return render_template('result.html', filename=filename, hash=file_hash)
    return render_template('upload.html')

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    if request.method == 'POST':
        file = request.files['document']
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            file_hash = calculate_hash(filepath)

            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT hash FROM documentos WHERE filename = %s", (filename,))
            row = cursor.fetchone()
            conn.close()

            original_hash = row['hash'] if row else None
            is_authentic = (file_hash == original_hash)

            return render_template('result.html', filename=filename, hash=file_hash, authentic=is_authentic)
    return render_template('verify.html')

if __name__ == '__main__':
    app.run(debug=True)
