# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import csv
import io
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
DATABASE = 'fmea.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Utility functions

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

# Authentication decorators

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = query_db('SELECT * FROM user WHERE id = ?', [session['user_id']], one=True)
        if not user or user['role'] != 'admin':
            flash('Keine Berechtigung für diese Aktion.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM user WHERE username = ?', [username], one=True)

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Willkommen, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Ungültige Anmeldedaten!', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sie wurden erfolgreich abgemeldet.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    entries = query_db('SELECT * FROM fmea_entry ORDER BY created_at DESC')

    for entry in entries:
        s, o, d = entry['severity'], entry['occurrence'], entry['detection']
        rpn = s * o * d
        entry['rpn'] = rpn
        entry['risk_level'] = 'high' if rpn > 100 else 'medium' if rpn > 50 else 'low'

    stats = {
        'total': len(entries),
        'high_risk': len([e for e in entries if e['rpn'] > 100]),
        'open': len([e for e in entries if e['status'] == 'Offen']),
        'completed': len([e for e in entries if e['status'] == 'Abgeschlossen']),
    }
    stats['completion_rate'] = round((stats['completed'] / stats['total'] * 100) if stats['total'] > 0 else 0, 1)

    return render_template('dashboard.html', entries=entries, stats=stats)

@app.route('/export_csv')
@login_required
def export_csv():
    entries = query_db('SELECT * FROM fmea_entry')

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')

    headers = [
        'Funktion', 'Fehlerart', 'Fehlerfolge', 'Auftretenswahrscheinlichkeit',
        'Fehlerursache', 'Auftreten', 'Prüfmaßnahme', 'Entdeckung',
        'RPN', 'Maßnahmen', 'Status', 'Erstellt am'
    ]
    writer.writerow(headers)

    for entry in entries:
        rpn = entry['severity'] * entry['occurrence'] * entry['detection']
        writer.writerow([
            entry['function'], entry['failure_mode'], entry['failure_effect'], entry['severity'],
            entry['failure_cause'], entry['occurrence'], entry['test_method'], entry['detection'],
            rpn, entry['actions'], entry['status'], entry['created_at']
        ])

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=FMEA_Export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv; charset=utf-8'
    return response

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)