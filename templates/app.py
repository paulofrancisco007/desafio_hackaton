import os
import hashlib
import json
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_wtf import FlaskForm
import mysql.connector
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, Optional

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# Configurações
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'database': os.environ.get('DB_NAME', 'govdocs')
}

app.config.update(
    UPLOAD_FOLDER='uploads',
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Classes de Formulário

class LoginForm(FlaskForm):
    cpf = StringField(
        'CPF',
        # remove tudo que não for dígito antes de validar
        filters=[lambda v: re.sub(r'\D', '', v or '')],
        validators=[
            DataRequired(message="O campo CPF é obrigatório."),
            Regexp(r'^\d{11}$', message="Digite apenas os 11 dígitos do CPF.")])
    senha = PasswordField(
        'Senha',
        validators=[DataRequired(message="O campo senha é obrigatório.")]
    )
    submit = SubmitField('Entrar')

class CadastroForm(FlaskForm):
    nome_completo = StringField('Nome Completo', validators=[
        DataRequired(),
        Length(min=5, max=100)
    ])
    cpf = StringField(
        'CPF',
        filters=[lambda v: re.sub(r'\D', '', v or '')],
        validators=[
            DataRequired(),
            Regexp(r'^\d{11}$', message="Digite apenas os 11 dígitos do CPF.")
        ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    telefone = StringField('Telefone', validators=[
        DataRequired(),
        Regexp(r'^\(\d{2}\) \d{5}-\d{4}$')
    ])
    senha = PasswordField('Senha', validators=[
        DataRequired(),
        Length(min=8)
    ])
    confirmar_senha = PasswordField('Confirmar Senha', validators=[
        DataRequired(),
        EqualTo('senha')
    ])
    termos = BooleanField('Termos de uso e privacidade', validators=[DataRequired()])
    submit = SubmitField('Criar Conta')


# ===== Configuração do Banco de Dados =====
def get_db():
    return mysql.connector.connect(
        host=app.config['DB_HOST'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD'],
        database=app.config['DB_NAME']
    )
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
    conn = None
    try:
        # Primeiro conecta sem especificar o banco de dados
        temp_config = DB_CONFIG.copy()
        temp_config.pop('database', None)
        
        conn = mysql.connector.connect(**temp_config)
        cursor = conn.cursor()
        
        # Cria o banco de dados se não existir
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        # Criação das tabelas
        tables = [
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome_completo VARCHAR(100) NOT NULL,
                cpf VARCHAR(14) UNIQUE,
                email VARCHAR(255) UNIQUE,
                telefone VARCHAR(15),
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS documentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                hash VARCHAR(64) NOT NULL,
                user_id INT NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata JSON,
                is_signed BOOLEAN DEFAULT FALSE,
                signed_by INT NULL,
                signed_at TIMESTAMP NULL,
                signature_info JSON,
                FOREIGN KEY (user_id) REFERENCES usuarios(id),
                FOREIGN KEY (signed_by) REFERENCES usuarios(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS assinaturas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                documento_id INT NOT NULL,
                hash_assinatura VARCHAR(64) NOT NULL,
                data_assinatura TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id),
                FOREIGN KEY (documento_id) REFERENCES documentos(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS auditoria (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                acao VARCHAR(50) NOT NULL,
                descricao TEXT,
                data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS assinaturas_pendentes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                documento_id INT NOT NULL,
                remetente_id INT NOT NULL,
                destinatario_id INT NOT NULL,
                mensagem TEXT,
                status ENUM('pendente', 'assinado', 'rejeitado') DEFAULT 'pendente',
                observacao TEXT,
                atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (documento_id) REFERENCES documentos(id),
                FOREIGN KEY (remetente_id) REFERENCES usuarios(id),
                FOREIGN KEY (destinatario_id) REFERENCES usuarios(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS notificacoes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                mensagem TEXT NOT NULL,
                tipo VARCHAR(20) NOT NULL,
                documento_id INT,
                lida BOOLEAN DEFAULT FALSE,
                criada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id),
                FOREIGN KEY (documento_id) REFERENCES documentos(id)
            )
            """
        ]

        for table in tables:
            cursor.execute(table)

        # Verifica se o usuário admin já existe
        cursor.execute("SELECT id FROM usuarios WHERE email = 'admin@admin.com'")
        if not cursor.fetchone():
            password_hash = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO usuarios 
                (nome_completo, email, password_hash, is_admin) 
                VALUES (%s, %s, %s, TRUE)
            """, ('Administrador', 'admin@admin.com', password_hash))
        
        conn.commit()
        print("Banco de dados inicializado com sucesso!")
        
    except mysql.connector.Error as err:
        print(f"Erro ao inicializar banco de dados: {err}")
        raise
    finally:
        if conn and conn.is_connected():
            conn.close()
init_database()

def get_db():
    """Retorna uma conexão com o banco de dados"""
    return mysql.connector.connect(**DB_CONFIG)

def log_audit(user_id, action, description, extra_data=None):
    """Registra ação na auditoria"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auditoria (user_id, acao, descricao, extra_data)
            VALUES (%s, %s, %s, %s)
        """, (user_id, action, description, json.dumps(extra_data) if extra_data else None))
        conn.commit()
    except Exception as e:
        print(f"Erro ao registrar auditoria: {e}")
    finally:
        if conn.is_connected():
            conn.close()

# ===== Funções Auxiliares =====
def add_visual_signature(input_pdf_path, output_pdf_path, signature_text):
    """Adiciona um carimbo visual de assinatura em cada página do PDF"""
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()

    for page_number, page in enumerate(reader.pages):
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=letter)
        can.setFont("Helvetica", 8)
        can.drawString(40, 30, signature_text)
        can.save()
        packet.seek(0)
        signature_pdf = PdfReader(packet)
        signature_page = signature_pdf.pages[0]
        page.merge_page(signature_page)
        writer.add_page(page)

    with open(output_pdf_path, 'wb') as output_file:
        writer.write(output_file)

def calculate_hash(filepath):
    """Calcula hash SHA-256 de um arquivo"""
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def validate_file(file):
    filename = file.filename
    if filename.endswith('.pdf'):
        try:
            file.seek(0)
            reader = PdfReader(file)
            if len(reader.pages) == 0:
                return False, "PDF inválido"
            file.seek(0)  # ⚠️ ESTA LINHA PARA NÃO CORROMPER O SALVAMENTO
        except Exception as e:
            print(f"Erro ao validar PDF: {e}")  # opcional, para debug
            return False, "PDF corrompido"
    return True, ""

# ===== Rotas Principais =====
# Adicione esta função auxiliar que estava faltando
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

# Corrigindo a rota de assinatura (erro de digitação)
@app.route('/document/<int:doc_id>/sign', methods=['GET', 'POST'])
@login_required
def sign_document(doc_id):
    if request.method == 'GET':
        return render_template('sign.html', doc_id=doc_id)

    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # 1. Busca o documento
        cursor.execute("""
            SELECT filename, original_filename FROM documentos 
            WHERE id = %s AND user_id = %s
        """, (doc_id, session['user_id']))
        document = cursor.fetchone()

        if not document:
            flash('Documento não encontrado ou acesso negado', 'danger')
            return redirect(url_for('index'))

        # 2. Caminhos
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        temp_signed_path = os.path.join(app.config['UPLOAD_FOLDER'], f"signed_{document['filename']}")

        # 3. Gera assinatura hash + assinatura visual
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        assinatura_hash = hashlib.sha256(
            f"{session['user_id']}{file_hash}{datetime.now().isoformat()}".encode()
        ).hexdigest()

        # 4. Texto visível da assinatura no PDF
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M")
        assinatura_visual = f"Sistema GovDocs RN - Documento assinado em {timestamp} por {session['user']} - ID: {doc_id}"

        # 5. Aplica a assinatura visual no PDF
        add_visual_signature(filepath, temp_signed_path, assinatura_visual)

        # 6. Substitui o arquivo original (ou mantenha os dois, se quiser histórico)
        os.replace(temp_signed_path, filepath)

        # 7. Registra a assinatura no banco
        cursor.execute("""
            INSERT INTO assinaturas (user_id, documento_id, hash_assinatura)
            VALUES (%s, %s, %s)
        """, (session['user_id'], doc_id, assinatura_hash))

        cursor.execute("""
            UPDATE documentos SET
                is_signed = TRUE,
                signed_by = %s,
                signed_at = NOW(),
                signature_info = %s
            WHERE id = %s
        """, (
            session['user_id'],
            json.dumps({
                'metodo': 'hash_sha256_visual',
                'assinatura': assinatura_hash,
                'valido': True,
                'assinatura_visual': assinatura_visual
            }),
            doc_id
        ))

        conn.commit()
        flash('Documento assinado com sucesso!', 'success')
        return redirect(url_for('document_detail', doc_id=doc_id))

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f'Erro na assinatura: {str(e)}', 'danger')
        return redirect(url_for('document_detail', doc_id=doc_id))
        
    finally:
        if conn and conn.is_connected():
            conn.close()

# ===== Rotas de Verificação =====
@app.route('/verify_metadata', methods=['GET', 'POST'])
@login_required
def verify_metadata():
    if request.method == 'POST':
        # 1. Recebe o arquivo
        file = request.files.get('document')
        if not file or file.filename == '':
            flash('Nenhum arquivo selecionado', 'danger')
            return redirect(url_for('verify_metadata'))

        # 2. Salva temporariamente
        filename = secure_filename(file.filename)
        tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"verify_{filename}")
        file.save(tmp_path)

        # 3. Extrai metadados
        metadata = extract_metadata(tmp_path)

        # 4. Limpa o arquivo temporário
        try:
            os.remove(tmp_path)
        except OSError:
            pass

        # 5. Renderiza o template mostrando os metadados
        return render_template('verify_metadata.html', metadata=metadata, filename=filename)

    # GET: exibe o formulário
    return render_template('verify_metadata.html', metadata=None, filename=None)


# ===== Rotas Principais =====
@app.route('/', endpoint='index')
def index():
    if 'user' in session:
        conn = None
        try:
            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT id, original_filename, upload_date, is_signed 
                FROM documentos WHERE user_id = %s 
                ORDER BY upload_date DESC LIMIT 5
            """, (session['user_id'],))
            docs = cursor.fetchall()
            return render_template('index.html', docs=docs)
        except Exception as e:
            flash(f'Erro ao carregar documentos: {str(e)}', 'danger')
        finally:
            if conn and conn.is_connected(): conn.close()
    return render_template('index.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    form = CadastroForm(request.form)
    if form.validate_on_submit():
        conn = None
        try:
            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            
            cpf_limpo = re.sub(r'[^0-9]', '', form.cpf.data)
            telefone_limpo = re.sub(r'[^0-9]', '', form.telefone.data)
            
            cursor.execute("SELECT id FROM usuarios WHERE cpf = %s OR email = %s", 
                          (cpf_limpo, form.email.data))
            if cursor.fetchone():
                flash('CPF ou email já cadastrados', 'danger')
                return redirect(url_for('cadastro'))
            
            password_hash = generate_password_hash(form.senha.data)
            cursor.execute("""
                INSERT INTO usuarios 
                (nome_completo, cpf, email, telefone, password_hash) 
                VALUES (%s, %s, %s, %s, %s)
            """, (
                form.nome_completo.data,
                cpf_limpo,
                form.email.data,
                telefone_limpo,
                password_hash
            ))
            
            conn.commit()
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            if conn: conn.rollback()
            flash(f'Erro no cadastro: {str(e)}', 'danger')
        finally:
            if conn and conn.is_connected(): conn.close()
    
    return render_template('cadastro.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = None
        try:
            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            
            cpf_limpo = re.sub(r'\D', '', form.cpf.data)

            cursor.execute("""
                SELECT id, nome_completo, password_hash, is_admin
                FROM usuarios
                WHERE cpf = %s
            """, (cpf_limpo,))
            
            usuario = cursor.fetchone()
            if usuario and check_password_hash(usuario['password_hash'], form.senha.data):
                session.update({
                    'user': usuario['nome_completo'],
                    'user_id': usuario['id'],
                    'is_admin': usuario['is_admin']
                })
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('tela'))
            
            flash('Email ou senha incorretos', 'danger')
        except Exception as e:
            flash(f'Erro no login: {str(e)}', 'danger')
        finally:
            if conn and conn.is_connected(): conn.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('index'))

@app.route("/perfil")
def perfil():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT nome_completo, cpf, email, telefone FROM usuarios WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()

    if not user:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("login"))

    # Formata o CPF
    cpf_formatado = user["cpf"]
    cpf_puro = re.sub(r'\D', '', cpf_formatado)
    if len(cpf_puro) == 11:
        cpf_formatado = f"{cpf_puro[:3]}.{cpf_puro[3:6]}.{cpf_puro[6:9]}-{cpf_puro[9:]}"

    return render_template(
        "perfil.html",
        nome_completo=user["nome_completo"],
        cpf=cpf_formatado,
        email=user["email"],
        telefone=user["telefone"]
    )

@app.route('/perfil/editar', methods=['POST'])
@login_required
def perfil_editar():
    nome      = request.form['nome_completo']
    cpf       = re.sub(r'\D','', request.form['cpf'])
    email     = request.form['email']
    telefone  = re.sub(r'\D','', request.form['telefone'])
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios
           SET nome_completo=%s,
               cpf=%s,
               email=%s,
               telefone=%s
         WHERE id=%s
    """, (nome, cpf, email, telefone, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Perfil atualizado com sucesso!', 'success')
    return redirect(url_for('perfil'))

@app.route('/tela')
@login_required
def tela():
    nome = session.get('user', 'Usuário')
    return render_template('tela.html', nome_completo=nome)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    # Busca usuários para popular o select
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nome_completo FROM usuarios WHERE id != %s ORDER BY nome_completo", 
                   (session['user_id'],))
    users = cursor.fetchall()
    cursor.close()

    if request.method == 'POST':
        # 1) Validação e salvamento do arquivo (seu código atual)…
        file = request.files['document']
        filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file_hash = calculate_hash(filepath)
        metadata = extract_metadata(filepath)

        # Grava em documentos
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO documentos 
              (filename, original_filename, hash, user_id, metadata)
            VALUES (%s, %s, %s, %s, %s)
        """, (filename, file.filename, file_hash, session['user_id'], json.dumps(metadata)))
        doc_id = cursor.lastrowid

        # 2) Agora, a parte de enviar para assinatura:
        recipient_id = request.form.get('recipient_id')
        message      = request.form.get('message', '')
        if recipient_id:
            # inserção em assinaturas_pendentes
            cursor.execute("""
                INSERT INTO assinaturas_pendentes
                  (documento_id, remetente_id, destinatario_id, mensagem, status)
                VALUES (%s, %s, %s, %s, 'pendente')
            """, (doc_id, session['user_id'], recipient_id, message))

            # opcional: notificação
            cursor.execute("""
                INSERT INTO notificacoes
                  (user_id, mensagem, tipo, documento_id)
                VALUES (%s, %s, %s, %s)
            """, (
                recipient_id,
                f"Novo documento para assinar: {file.filename}",
                'assinatura_pendente',
                doc_id
            ))

        conn.commit()
        cursor.close()
        conn.close()

        flash('Documento enviado e encaminhado para assinatura com sucesso!', 'success')
        return redirect(url_for('document_detail', doc_id=doc_id))

    # GET: mostra a tela preenchendo o select
    return render_template('upload.html', users=users)

@app.route('/document/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT filename, original_filename 
            FROM documentos 
            WHERE id = %s AND user_id = %s
        """, (doc_id, session['user_id']))
        document = cursor.fetchone()
        
        if not document:
            flash('Documento não encontrado ou acesso negado', 'danger')
            return redirect(url_for('index'))
            
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        
        if not os.path.exists(filepath):
            flash('Arquivo não encontrado no servidor', 'danger')
            return redirect(url_for('document_detail', doc_id=doc_id))
        
        # Determina o mimetype correto
        mimetype = 'application/octet-stream'
        if document['filename'].lower().endswith('.pdf'):
            mimetype = 'application/pdf'
        elif document['filename'].lower().endswith(('.jpg', '.jpeg')):
            mimetype = 'image/jpeg'
        elif document['filename'].lower().endswith('.png'):
            mimetype = 'image/png'
            
        return send_file(
            filepath,
            as_attachment=True,
            download_name=document['original_filename'],
            mimetype=mimetype
        )
        
    except Exception as e:
        flash(f'Erro ao baixar documento: {str(e)}', 'danger')
        return redirect(url_for('document_detail', doc_id=doc_id))
        
    finally:
        if conn.is_connected():
            conn.close()

@app.route('/document/<int:doc_id>/send_to_sign', methods=['GET', 'POST'])
@login_required
def send_to_sign(doc_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Verifica se o documento pertence ao usuário
        cursor.execute("SELECT * FROM documentos WHERE id = %s AND user_id = %s", (doc_id, session['user_id']))
        document = cursor.fetchone()
        
        if not document:
            flash('Documento não encontrado ou acesso negado', 'danger')
            return redirect(url_for('index'))

        if request.method == 'GET':
            # Busca todos os usuários exceto o atual
            cursor.execute("SELECT id, nome_completo FROM usuarios WHERE id != %s", (session['user_id'],))
            users = cursor.fetchall()
            return render_template('send_to_sign.html', document=document, users=users)

        # Processa o POST
        recipient_id = request.form.get('recipient_id')
        message = request.form.get('message', '')

        if not recipient_id:
            flash('Selecione um destinatário válido', 'danger')
            return redirect(url_for('send_to_sign', doc_id=doc_id))

        # Registra a solicitação de assinatura
        cursor.execute("""
            INSERT INTO assinaturas_pendentes 
            (documento_id, remetente_id, destinatario_id, mensagem, status) 
            VALUES (%s, %s, %s, %s, 'pendente')
        """, (doc_id, session['user_id'], recipient_id, message))
        
        # Cria notificação para o destinatário
        cursor.execute("""
            INSERT INTO notificacoes 
            (user_id, mensagem, tipo, documento_id) 
            VALUES (%s, %s, %s, %s)
        """, (
            recipient_id,
            f"Novo documento para assinar: {document['original_filename']}",
            'assinatura_pendente',
            doc_id
        ))
        
        conn.commit()
        flash('Documento enviado para assinatura com sucesso!', 'success')
        return redirect(url_for('document_detail', doc_id=doc_id))
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao enviar documento: {str(e)}', 'danger')
        return redirect(url_for('send_to_sign', doc_id=doc_id))
    finally:
        if conn.is_connected():
            conn.close()

@app.route('/pending_signatures')
@login_required
def pending_signatures():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT ap.id, d.original_filename, u.nome_completo as remetente, 
               ap.criado_em, ap.status, d.id as doc_id
        FROM assinaturas_pendentes ap
        JOIN documentos d ON ap.documento_id = d.id
        JOIN usuarios u ON ap.remetente_id = u.id
        WHERE ap.destinatario_id = %s AND ap.status = 'pendente'
    """, (session['user_id'],))
    
    pending_docs = cursor.fetchall()
    conn.close()
    return render_template('pending_signatures.html', documents=pending_docs)

@app.route('/process_signature/<int:request_id>', methods=['POST'])
@login_required
def process_signature(request_id):
    action = request.form.get('action')  # 'sign' ou 'reject'
    observation = request.form.get('observation', '')
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Verifica se a solicitação é para o usuário atual
        cursor.execute("""
            SELECT documento_id, remetente_id 
            FROM assinaturas_pendentes 
            WHERE id = %s AND destinatario_id = %s
        """, (request_id, session['user_id']))
        request_data = cursor.fetchone()
        
        if not request_data:
            flash('Solicitação não encontrada', 'danger')
            return redirect(url_for('pending_signatures'))
        
        doc_id = request_data['documento_id']
        sender_id = request_data['remetente_id']
        
        if action == 'sign':
            # Chama a função de assinatura
            cursor.execute("""
                UPDATE assinaturas_pendentes 
                SET status = 'assinado', observacao = %s 
                WHERE id = %s
            """, (observation, request_id))
            
            # Aqui você pode adicionar a lógica de assinatura real
            # ou redirecionar para a rota de assinatura
            flash('Documento assinado com sucesso!', 'success')
            
        elif action == 'reject':
            cursor.execute("""
                UPDATE assinaturas_pendentes 
                SET status = 'rejeitado', observacao = %s 
                WHERE id = %s
            """, (observation, request_id))
            flash('Documento rejeitado', 'info')
        
        conn.commit()
        
        # Registrar notificação para o remetente
        cursor.execute("""
            INSERT INTO notificacoes 
            (user_id, mensagem, tipo, documento_id) 
            VALUES (%s, %s, %s, %s)
        """, (
            sender_id,
            f"Seu documento foi {action} por {session['user']}",
            'assinatura' if action == 'sign' else 'rejeicao',
            doc_id
        ))
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao processar assinatura: {str(e)}', 'danger')
    finally:
        if conn.is_connected():
            conn.close()
    
    return redirect(url_for('pending_signatures'))

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
            SELECT d.hash, d.original_filename, u.nome_completo
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
                           uploaded_by=original['nome_completo'] if original else None)
    
    return render_template('verify.html')

@app.route('/document/<int:doc_id>')
@login_required
def document_detail(doc_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT d.*, u.nome_completo 
        FROM documentos d
        JOIN usuarios u ON d.user_id = u.id
        WHERE d.id = %s
    """, (doc_id,))
    
    document = cursor.fetchone()
    conn.close()
    
    print("Document object:", document)  # Adicione esta linha para debug
    
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

@app.route('/notifications')
@login_required
def notifications():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Busca notificações não lidas
    cursor.execute("""
        SELECT n.*, d.original_filename 
        FROM notificacoes n
        LEFT JOIN documentos d ON n.documento_id = d.id
        WHERE n.user_id = %s AND n.lida = FALSE
        ORDER BY n.criada_em DESC
    """, (session['user_id'],))
    
    unread = cursor.fetchall()
    
    # Busca notificações lidas recentemente
    cursor.execute("""
        SELECT n.*, d.original_filename 
        FROM notificacoes n
        LEFT JOIN documentos d ON n.documento_id = d.id
        WHERE n.user_id = %s AND n.lida = TRUE
        ORDER BY n.criada_em DESC
        LIMIT 5
    """, (session['user_id'],))
    
    read = cursor.fetchall()
    conn.close()
    
    return render_template('notifications.html', unread=unread, read=read)

@app.route('/notification/<int:notification_id>/mark_as_read')
@login_required
def mark_notification_as_read(notification_id):
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE notificacoes 
            SET lida = TRUE 
            WHERE id = %s AND user_id = %s
        """, (notification_id, session['user_id']))
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao marcar notificação: {str(e)}', 'danger')
    finally:
        if conn.is_connected():
            conn.close()
    
    return redirect(url_for('notifications'))

@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT COUNT(*) as count FROM notificacoes WHERE user_id = %s AND lida = FALSE", (session['user_id'],))
        unread_count = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT n.*, d.original_filename 
            FROM notificacoes n
            LEFT JOIN documentos d ON n.documento_id = d.id
            WHERE n.user_id = %s AND n.lida = FALSE
            ORDER BY n.criada_em DESC
            LIMIT 5
        """, (session['user_id'],))
        unread = cursor.fetchall()
        
        conn.close()
        
        print("DEBUG - Notifications unread:", unread)  # Adicione esta linha
        print("DEBUG - First notification type:", type(unread[0]) if unread else "Empty")
        
        return {
            'unread_count': unread_count,
            'notifications': {
                'unread': unread
            }
        }
    return {}

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
        SELECT d.id, d.original_filename, u.nome_completo, d.upload_date 
        FROM documentos d
        JOIN usuarios u ON d.user_id = u.id
        ORDER BY d.upload_date DESC LIMIT 10
    """)
    recent_docs = cursor.fetchall()
    
    # Atividades recentes
    cursor.execute("""
        SELECT a.acao, a.descricao, a.data, u.nome_completo
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
            SELECT d.id, d.original_filename, d.upload_date, u.nome_completo
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

@app.route('/api/notifications/count')
@login_required
def api_notifications_count():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM notificacoes WHERE user_id = %s AND lida = FALSE", (session['user_id'],))
    count = cursor.fetchone()[0]
    conn.close()
    return jsonify({'unread_count': count})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)