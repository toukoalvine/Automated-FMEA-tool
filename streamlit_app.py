# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import csv
import io
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fmea.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FMEAEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    function = db.Column(db.String(200), nullable=False)
    failure_mode = db.Column(db.String(200), nullable=False)
    failure_effect = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Integer, nullable=False)  # 1-10
    failure_cause = db.Column(db.Text, nullable=False)
    occurrence = db.Column(db.Integer, nullable=False)  # 1-10
    test_method = db.Column(db.String(200), nullable=False)
    detection = db.Column(db.Integer, nullable=False)  # 1-10
    actions = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default='Offen')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def rpn(self):
        return self.severity * self.occurrence * self.detection

    @property
    def risk_level(self):
        rpn = self.rpn
        if rpn > 100:
            return 'high'
        elif rpn > 50:
            return 'medium'
        else:
            return 'low'

    def to_dict(self):
        return {
            'id': self.id,
            'function': self.function,
            'failure_mode': self.failure_mode,
            'failure_effect': self.failure_effect,
            'severity': self.severity,
            'failure_cause': self.failure_cause,
            'occurrence': self.occurrence,
            'test_method': self.test_method,
            'detection': self.detection,
            'actions': self.actions,
            'status': self.status,
            'rpn': self.rpn,
            'risk_level': self.risk_level,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M')
        }

class Action(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    assigned_to = db.Column(db.String(100))
    priority = db.Column(db.String(20), default='Mittel')  # Niedrig, Mittel, Hoch
    status = db.Column(db.String(50), default='Offen')
    due_date = db.Column(db.Date)
    fmea_entry_id = db.Column(db.Integer, db.ForeignKey('fmea_entry.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    fmea_entry = db.relationship('FMEAEntry', backref=db.backref('related_actions', lazy=True))

# Authentication decorator
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
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
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
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Willkommen, {user.username}!', 'success')
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
    # Get filter parameters
    search = request.args.get('search', '')
    risk_filter = request.args.get('risk_filter', '')
    status_filter = request.args.get('status_filter', '')
    
    # Build query
    query = FMEAEntry.query
    
    if search:
        query = query.filter(
            db.or_(
                FMEAEntry.function.contains(search),
                FMEAEntry.failure_mode.contains(search),
                FMEAEntry.failure_cause.contains(search),
                FMEAEntry.failure_effect.contains(search)
            )
        )
    
    if status_filter:
        query = query.filter(FMEAEntry.status == status_filter)
    
    entries = query.order_by(FMEAEntry.created_at.desc()).all()
    
    # Apply risk filter (after query since RPN is calculated)
    if risk_filter:
        if risk_filter == 'high':
            entries = [e for e in entries if e.rpn > 100]
        elif risk_filter == 'medium':
            entries = [e for e in entries if 50 <= e.rpn <= 100]
        elif risk_filter == 'low':
            entries = [e for e in entries if e.rpn < 50]
    
    # Calculate statistics
    total_entries = len(entries)
    high_risk_count = len([e for e in entries if e.rpn > 100])
    open_count = len([e for e in entries if e.status == 'Offen'])
    completed_count = len([e for e in entries if e.status == 'Abgeschlossen'])
    
    stats = {
        'total': total_entries,
        'high_risk': high_risk_count,
        'open': open_count,
        'completed': completed_count,
        'completion_rate': round((completed_count / total_entries * 100) if total_entries > 0 else 0, 1)
    }
    
    return render_template('dashboard.html', entries=entries, stats=stats,
                         search=search, risk_filter=risk_filter, status_filter=status_filter)

@app.route('/add_entry', methods=['GET', 'POST'])
@login_required
def add_entry():
    if request.method == 'POST':
        try:
            entry = FMEAEntry(
                function=request.form['function'],
                failure_mode=request.form['failure_mode'],
                failure_effect=request.form['failure_effect'],
                severity=int(request.form['severity']),
                failure_cause=request.form['failure_cause'],
                occurrence=int(request.form['occurrence']),
                test_method=request.form['test_method'],
                detection=int(request.form['detection']),
                actions=request.form.get('actions', ''),
                status=request.form['status'],
                created_by=session['user_id']
            )
            
            db.session.add(entry)
            db.session.commit()
            flash('FMEA-Eintrag erfolgreich hinzugefügt!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Fehler beim Speichern: {str(e)}', 'error')
    
    return render_template('add_entry.html')

@app.route('/edit_entry/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_entry(id):
    entry = FMEAEntry.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            entry.function = request.form['function']
            entry.failure_mode = request.form['failure_mode']
            entry.failure_effect = request.form['failure_effect']
            entry.severity = int(request.form['severity'])
            entry.failure_cause = request.form['failure_cause']
            entry.occurrence = int(request.form['occurrence'])
            entry.test_method = request.form['test_method']
            entry.detection = int(request.form['detection'])
            entry.actions = request.form.get('actions', '')
            entry.status = request.form['status']
            entry.updated_at = datetime.utcnow()
            
            db.session.commit()
            flash('FMEA-Eintrag erfolgreich aktualisiert!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Fehler beim Aktualisieren: {str(e)}', 'error')
    
    return render_template('edit_entry.html', entry=entry)

@app.route('/delete_entry/<int:id>')
@admin_required
def delete_entry(id):
    entry = FMEAEntry.query.get_or_404(id)
    try:
        db.session.delete(entry)
        db.session.commit()
        flash('FMEA-Eintrag erfolgreich gelöscht!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Fehler beim Löschen: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/actions')
@admin_required
def manage_actions():
    actions = Action.query.order_by(Action.created_at.desc()).all()
    return render_template('actions.html', actions=actions)

@app.route('/add_action', methods=['GET', 'POST'])
@admin_required
def add_action():
    if request.method == 'POST':
        try:
            due_date = None
            if request.form.get('due_date'):
                due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d').date()
            
            action = Action(
                title=request.form['title'],
                description=request.form.get('description', ''),
                assigned_to=request.form.get('assigned_to', ''),
                priority=request.form['priority'],
                status=request.form['status'],
                due_date=due_date,
                fmea_entry_id=request.form.get('fmea_entry_id') or None,
                created_by=session['user_id']
            )
            
            db.session.add(action)
            db.session.commit()
            flash('Maßnahme erfolgreich hinzugefügt!', 'success')
            return redirect(url_for('manage_actions'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Fehler beim Speichern: {str(e)}', 'error')
    
    fmea_entries = FMEAEntry.query.all()
    return render_template('add_action.html', fmea_entries=fmea_entries)

@app.route('/edit_action/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_action(id):
    action = Action.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            due_date = None
            if request.form.get('due_date'):
                due_date = datetime.strptime(request.form['due_date'], '%Y-%m-%d').date()
            
            action.title = request.form['title']
            action.description = request.form.get('description', '')
            action.assigned_to = request.form.get('assigned_to', '')
            action.priority = request.form['priority']
            action.status = request.form['status']
            action.due_date = due_date
            action.fmea_entry_id = request.form.get('fmea_entry_id') or None
            action.updated_at = datetime.utcnow()
            
            db.session.commit()
            flash('Maßnahme erfolgreich aktualisiert!', 'success')
            return redirect(url_for('manage_actions'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Fehler beim Aktualisieren: {str(e)}', 'error')
    
    fmea_entries = FMEAEntry.query.all()
    return render_template('edit_action.html', action=action, fmea_entries=fmea_entries)

@app.route('/delete_action/<int:id>')
@admin_required
def delete_action(id):
    action = Action.query.get_or_404(id)
    try:
        db.session.delete(action)
        db.session.commit()
        flash('Maßnahme erfolgreich gelöscht!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Fehler beim Löschen: {str(e)}', 'error')
    
    return redirect(url_for('manage_actions'))

@app.route('/export_csv')
@login_required
def export_csv():
    entries = FMEAEntry.query.all()
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    
    # Header
    headers = [
        'Funktion', 'Fehlerart', 'Fehlerfolge', 'Auftretenswahrscheinlichkeit',
        'Fehlerursache', 'Auftreten', 'Prüfmaßnahme', 'Entdeckung',
        'RPN', 'Maßnahmen', 'Status', 'Erstellt am'
    ]
    writer.writerow(headers)
    
    # Data
    for entry in entries:
        writer.writerow([
            entry.function,
            entry.failure_mode,
            entry.failure_effect,
            entry.severity,
            entry.failure_cause,
            entry.occurrence,
            entry.test_method,
            entry.detection,
            entry.rpn,
            entry.actions or '',
            entry.status,
            entry.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    
    output.seek(0)
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=FMEA_Export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv; charset=utf-8'
    
    return response

@app.route('/api/statistics')
@login_required
def api_statistics():
    entries = FMEAEntry.query.all()
    
    total = len(entries)
    high_risk = len([e for e in entries if e.rpn > 100])
    medium_risk = len([e for e in entries if 50 <= e.rpn <= 100])
    low_risk = len([e for e in entries if e.rpn < 50])
    
    open_count = len([e for e in entries if e.status == 'Offen'])
    in_progress = len([e for e in entries if e.status == 'In Bearbeitung'])
    completed = len([e for e in entries if e.status == 'Abgeschlossen'])
    
    return jsonify({
        'total_entries': total,
        'risk_distribution': {
            'high': high_risk,
            'medium': medium_risk,
            'low': low_risk
        },
        'status_distribution': {
            'open': open_count,
            'in_progress': in_progress,
            'completed': completed
        },
        'completion_rate': round((completed / total * 100) if total > 0 else 0, 1)
    })

def init_db():
    """Initialize database with sample data"""
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
    
    # Create regular user if not exists
    if not User.query.filter_by(username='user').first():
        user = User(username='user', role='user')
        user.set_password('user123')
        db.session.add(user)
    
    db.session.commit()
    
    # Add sample FMEA entries if none exist
    if FMEAEntry.query.count() == 0:
        admin_user = User.query.filter_by(username='admin').first()
        
        sample_entries = [
            FMEAEntry(
                function='Motor starten',
                failure_mode='Motor startet nicht',
                failure_effect='System funktioniert nicht, Produktionsausfall',
                severity=8,
                failure_cause='Defekte Zündkerze, leere Batterie',
                occurrence=3,
                test_method='Visuelle Prüfung, Spannungsmessung',
                detection=2,
                actions='Wartungsplan erstellen, Ersatzteile bevorraten',
                status='Offen',
                created_by=admin_user.id
            ),
            FMEAEntry(
                function='Bremssystem',
                failure_mode='Bremsen versagen',
                failure_effect='Sicherheitsrisiko, mögliche Unfälle',
                severity=10,
                failure_cause='Verschlissene Bremsbeläge, Leckage im System',
                occurrence=2,
                test_method='Regelmäßige Inspektion, Bremstest',
                detection=3,
                actions='Präventive Wartung alle 6 Monate',
                status='In Bearbeitung',
                created_by=admin_user.id
            ),
            FMEAEntry(
                function='Temperaturregelung',
                failure_mode='Überhitzung',
                failure_effect='Komponentenschäden, Systemausfall',
                severity=7,
                failure_cause='Defekter Temperatursensor, verstopfter Filter',
                occurrence=4,
                test_method='Temperaturüberwachung, Sensorkalibrierung',
                detection=4,
                actions='Redundante Sensoren installieren',
                status='Abgeschlossen',
                created_by=admin_user.id
            )
        ]
        
        for entry in sample_entries:
            db.session.add(entry)
        
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
