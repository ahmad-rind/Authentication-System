import os
import hashlib
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g

app = Flask(__name__)
app.secret_key = 'mdb_secret_key_2024'
DATABASE = os.path.join(os.path.dirname(__file__), 'mdb.db')

# ──────────────── DB helpers ────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student','instructor','admin')),
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked')),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Create default admin if not exists
        existing = db.execute("SELECT id FROM users WHERE email='maryam@admin.com'").fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (name,email,password_hash,role,status) VALUES (?,?,?,?,?)",
                ('Administrator', 'maryam@admin.com', hash_password('admin123'), 'admin', 'active')
            )
        db.commit()

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ──────────────── Auth decorators ────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash('Access denied.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# ──────────────── Routes ────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name  = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        pw    = request.form.get('password','')
        pw2   = request.form.get('confirm_password','')
        if not name or not email or not pw:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        if pw != pw2:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        if len(pw) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')
        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        db.execute(
            "INSERT INTO users (name,email,password_hash,role,status) VALUES (?,?,?,?,?)",
            (name, email, hash_password(pw), 'student', 'active')
        )
        db.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        pw    = request.form.get('password','')
        db    = get_db()
        user  = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or user['password_hash'] != hash_password(pw):
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')
        if user['status'] == 'blocked':
            flash('Your account has been blocked. Contact administrator.', 'danger')
            return render_template('login.html')
        session['user_id'] = user['id']
        session['name']    = user['name']
        session['role']    = user['role']
        flash(f'Welcome back, {user["name"]}!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_panel'))
    elif role == 'instructor':
        return redirect(url_for('instructor_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

@app.route('/student/dashboard')
@login_required
@role_required('student')
def student_dashboard():
    return render_template('student_dashboard.html')

@app.route('/instructor/dashboard')
@login_required
@role_required('instructor')
def instructor_dashboard():
    db = get_db()
    students = db.execute("SELECT id,name,email,status,created_at FROM users WHERE role='student' ORDER BY name").fetchall()
    return render_template('instructor_dashboard.html', students=students)

@app.route('/admin/panel')
@login_required
@role_required('admin')
def admin_panel():
    db    = get_db()
    users = db.execute("SELECT * FROM users ORDER BY role,name").fetchall()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/users/create', methods=['POST'])
@login_required
@role_required('admin')
def admin_create_user():
    name  = request.form.get('name','').strip()
    email = request.form.get('email','').strip().lower()
    pw    = request.form.get('password','')
    role  = request.form.get('role','student')
    if not name or not email or not pw or role not in ('student','instructor','admin'):
        flash('All fields required and role must be valid.', 'danger')
        return redirect(url_for('admin_panel'))
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        flash('Email already exists.', 'danger')
        return redirect(url_for('admin_panel'))
    db.execute(
        "INSERT INTO users (name,email,password_hash,role,status) VALUES (?,?,?,?,?)",
        (name, email, hash_password(pw), role, 'active')
    )
    db.commit()
    flash(f'User {name} created successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<int:uid>/block', methods=['POST'])
@login_required
@role_required('admin')
def admin_block_user(uid):
    if uid == session['user_id']:
        flash('You cannot block yourself.', 'danger')
        return redirect(url_for('admin_panel'))
    db = get_db()
    db.execute("UPDATE users SET status='blocked' WHERE id=?", (uid,))
    db.commit()
    flash('User blocked.', 'warning')
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<int:uid>/unblock', methods=['POST'])
@login_required
@role_required('admin')
def admin_unblock_user(uid):
    db = get_db()
    db.execute("UPDATE users SET status='active' WHERE id=?", (uid,))
    db.commit()
    flash('User unblocked.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required
@role_required('admin')
def admin_delete_user(uid):
    if uid == session['user_id']:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('admin_panel'))
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    flash('User deleted.', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<int:uid>/role', methods=['POST'])
@login_required
@role_required('admin')
def admin_change_role(uid):
    if uid == session['user_id']:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('admin_panel'))
    new_role = request.form.get('role')
    if new_role not in ('student','instructor','admin'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin_panel'))
    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    db.commit()
    flash('Role updated.', 'success')
    return redirect(url_for('admin_panel'))

# Initialize DB on module load (required for Vercel serverless)
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
