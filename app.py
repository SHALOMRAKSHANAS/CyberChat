import os
from flask import Flask, request, redirect, url_for, render_template, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
import uuid
import mimetypes


app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'doc', 'docx', 'bmp'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
DATABASE = 'messaging.db'

# Approved users and their secure passwords
APPROVED_USERS = {
    "Duck": "ShalomRakshanaS123",
    "Dog": "TejjalSpandanaaTG8947",
    "Buffalo": "KavinS123"
}

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT REFERENCES users(id),
                receiver_id TEXT REFERENCES users(id),
                message_type TEXT NOT NULL,
                content TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT FALSE
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages (sender_id, receiver_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages (receiver_id, is_read)")
        conn.commit()
        cur.close()

def preload_approved_users():
    with get_db() as conn:
        cur = conn.cursor()
        for username, password in APPROVED_USERS.items():
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                continue
            user_id = str(uuid.uuid4())
            password_hash = generate_password_hash(password)
            cur.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                        (user_id, username, password_hash))
        conn.commit()
        cur.close()

def authenticate_user(username, password):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()
        if not user:
            return None
        if check_password_hash(user["password_hash"], password):
            return user["id"]
        return None

def get_conversation_users(current_user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT u.id, u.username FROM users u
            JOIN messages m ON (u.id = m.sender_id OR u.id = m.receiver_id)
            WHERE u.id != ? AND (m.sender_id = ? OR m.receiver_id = ?)
        """, (current_user_id, current_user_id, current_user_id))
        users = cur.fetchall()
        cur.close()
        return [dict(row) for row in users]

def get_user(user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        cur.close()
        return dict(user) if user else None

def search_users(query, current_user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users WHERE LOWER(username) LIKE LOWER(?) AND id != ?",
                    (f"%{query}%", current_user_id))
        users = cur.fetchall()
        cur.close()
        return [dict(row) for row in users]

def save_message(sender_id, receiver_id, message_type, content):
    with get_db() as conn:
        cur = conn.cursor()
        message_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO messages (id, sender_id, receiver_id, message_type, content)
            VALUES (?, ?, ?, ?, ?)
        """, (message_id, sender_id, receiver_id, message_type, content))
        conn.commit()
        cur.close()

def get_messages(user_id, other_user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE messages SET is_read = TRUE WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE",
                    (other_user_id, user_id))
        conn.commit()
        cur.execute("""
            SELECT m.id, m.sender_id, m.receiver_id, m.message_type, m.content, m.sent_at,
                   sender.username AS sender_name, receiver.username AS receiver_name
            FROM messages m
            JOIN users sender ON m.sender_id = sender.id
            JOIN users receiver ON m.receiver_id = receiver.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.sent_at
        """, (user_id, other_user_id, other_user_id, user_id))
        messages = cur.fetchall()
        cur.close()
        return [dict(row) for row in messages]

def get_unread_count(user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT sender_id, COUNT(*) as count FROM messages WHERE receiver_id = ? AND is_read = FALSE GROUP BY sender_id",
                    (user_id,))
        results = cur.fetchall()
        cur.close()
        return {row["sender_id"]: row["count"] for row in results}

@app.route('/')
def index():
    if 'user_id' not in request.cookies:
        return render_template('login.html')
    return redirect(url_for('search'))

@app.route('/', methods=['POST'])
def handle_auth():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password or len(password) < 8:
        flash('Username and password (min 8 chars) required', 'error')
        return redirect(url_for('index'))

    user_id = authenticate_user(username, password)
    if not user_id:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))

    resp = redirect(url_for('search'))
    resp.set_cookie('user_id', user_id)
    resp.set_cookie('username', username)
    return resp

@app.route('/logout')
def logout():
    resp = redirect(url_for('index'))
    resp.delete_cookie('user_id')
    resp.delete_cookie('username')
    return resp

@app.route('/search')
def search():
    if 'user_id' not in request.cookies:
        return redirect(url_for('index'))
    current_user_id = request.cookies.get('user_id')
    query = request.args.get('q', '')
    search_results = get_conversation_users(current_user_id)
    if query:
        search_results = search_users(query, current_user_id)
    unread_counts = get_unread_count(current_user_id)
    return render_template('messaging.html',
                           user_id=current_user_id,
                           username=request.cookies.get('username'),
                           other_user=None,
                           messages=[],
                           search_results=search_results,
                           unread_counts=unread_counts)

@app.route('/chat/<user_id>')
def chat(user_id):
    if 'user_id' not in request.cookies:
        return redirect(url_for('index'))
    current_user_id = request.cookies.get('user_id')
    other_user = get_user(user_id)
    if not other_user:
        flash('User not found', 'error')
        return redirect(url_for('search'))
    messages = get_messages(current_user_id, user_id)
    unread_counts = get_unread_count(current_user_id)
    return render_template('messaging.html',
                           user_id=current_user_id,
                           username=request.cookies.get('username'),
                           other_user=other_user,
                           messages=messages,
                           search_results=[],
                           unread_counts=unread_counts)

@app.route('/check-messages/<other_user_id>')
def check_messages(other_user_id):
    if 'user_id' not in request.cookies:
        return jsonify({'error': 'Not authenticated'}), 401
    current_user_id = request.cookies.get('user_id')
    last_message_time = request.args.get('last_message_time')
    with get_db() as conn:
        query = """
            SELECT m.id, m.sender_id, m.receiver_id, m.message_type, m.content, m.sent_at, 
                   sender.username as sender_name
            FROM messages m
            JOIN users sender ON m.sender_id = sender.id
            WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        """
        params = [current_user_id, other_user_id, other_user_id, current_user_id]
        if last_message_time:
            query += " AND m.sent_at > ?"
            params.append(last_message_time)
        query += " ORDER BY m.sent_at"
        cursor = conn.execute(query, params)
        new_messages = [dict(row) for row in cursor.fetchall()]
        conn.execute(
            "UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0",
            (other_user_id, current_user_id)
        )
        unread_counts = get_unread_count(current_user_id)
        return jsonify({
            'new_messages': new_messages,
            'unread_counts': unread_counts
        })

@app.route('/send/<receiver_id>', methods=['POST'])
def send_message(receiver_id):
    if 'user_id' not in request.cookies:
        return redirect(url_for('index'))
    sender_id = request.cookies.get('user_id')
    message_text = request.form.get('message_text')
    file = request.files.get('file')
    if file and file.filename:
        if allowed_file(file.filename):
            filename = secure_filename(f"{sender_id}_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                if mime_type.startswith('image'):
                    message_type = 'image'
                elif mime_type.startswith('video'):
                    message_type = 'video'
                else:
                    message_type = 'document'
            else:
                message_type = 'document'
            save_message(sender_id, receiver_id, message_type, filename)
    if message_text and message_text.strip():
        save_message(sender_id, receiver_id, 'text', message_text.strip())
    return redirect(url_for('chat', user_id=receiver_id))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == '__main__':
    init_db()
    preload_approved_users()
    app.run(debug=True, port=5000)
