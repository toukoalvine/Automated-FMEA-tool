import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, date
import hashlib
import io
import csv
from typing import Optional, List, Dict, Any

# Database setup
DATABASE = 'fmea.db'

def init_db():
    """Initialize database with tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create FMEA entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fmea_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function TEXT NOT NULL,
            failure_mode TEXT NOT NULL,
            failure_effect TEXT NOT NULL,
            severity INTEGER NOT NULL,
            failure_cause TEXT NOT NULL,
            occurrence INTEGER NOT NULL,
            test_method TEXT NOT NULL,
            detection INTEGER NOT NULL,
            actions TEXT,
            status TEXT NOT NULL DEFAULT 'Offen',
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    # Enhanced Actions table with new fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            assigned_to TEXT,
            priority TEXT DEFAULT 'Mittel',
            status TEXT DEFAULT 'Offen',
            due_date DATE,
            fmea_entry_id INTEGER,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            -- New extended fields
            empfohlene_abstellmassnahmen TEXT,
            ausfuehrung_durch TEXT,
            verbesserter_zustand TEXT,
            verantwortlicher_name TEXT,
            datum_bis DATE,
            getroffene_massnahme TEXT,
            umgesetzt_am DATE,
            umgesetzt_durch TEXT,
            neue_auftretenswahrscheinlichkeit INTEGER,
            neues_auftreten INTEGER,
            neue_entdeckung INTEGER,
            neue_rpz INTEGER,
            
            FOREIGN KEY (fmea_entry_id) REFERENCES fmea_entries (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    # Add new columns to existing actions table if they don't exist
    cursor.execute("PRAGMA table_info(actions)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = [
        ('empfohlene_abstellmassnahmen', 'TEXT'),
        ('ausfuehrung_durch', 'TEXT'),
        ('verbesserter_zustand', 'TEXT'),
        ('verantwortlicher_name', 'TEXT'),
        ('datum_bis', 'DATE'),
        ('getroffene_massnahme', 'TEXT'),
        ('umgesetzt_am', 'DATE'),
        ('umgesetzt_durch', 'TEXT'),
        ('neue_auftretenswahrscheinlichkeit', 'INTEGER'),
        ('neues_auftreten', 'INTEGER'),
        ('neue_entdeckung', 'INTEGER'),
        ('neue_rpz', 'INTEGER')
    ]
    
    for column_name, column_type in new_columns:
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE actions ADD COLUMN {column_name} {column_type}")
    
    conn.commit()
    
    # Create default users if they don't exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Create admin user
        admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                      ('admin', admin_hash, 'admin'))
        
        # Create regular user
        user_hash = hashlib.sha256('user123'.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                      ('user', user_hash, 'user'))
        
        conn.commit()
        
        # Add sample FMEA entries
        sample_entries = [
            ('Motor starten', 'Motor startet nicht', 'System funktioniert nicht, Produktionsausfall', 8,
             'Defekte Zündkerze, leere Batterie', 3, 'Visuelle Prüfung, Spannungsmessung', 2,
             'Wartungsplan erstellen, Ersatzteile bevorraten', 'Offen', 1),
            ('Bremssystem', 'Bremsen versagen', 'Sicherheitsrisiko, mögliche Unfälle', 10,
             'Verschlissene Bremsbeläge, Leckage im System', 2, 'Regelmäßige Inspektion, Bremstest', 3,
             'Präventive Wartung alle 6 Monate', 'In Bearbeitung', 1),
            ('Temperaturregelung', 'Überhitzung', 'Komponentenschäden, Systemausfall', 7,
             'Defekter Temperatursensor, verstopfter Filter', 4, 'Temperaturüberwachung, Sensorkalibrierung', 4,
             'Redundante Sensoren installieren', 'Abgeschlossen', 1)
        ]
        
        for entry in sample_entries:
            cursor.execute('''
                INSERT INTO fmea_entries (function, failure_mode, failure_effect, severity, failure_cause,
                                        occurrence, test_method, detection, actions, status, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', entry)
        
        conn.commit()
    
    conn.close()

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hash: str) -> bool:
    """Verify password against hash"""
    return hashlib.sha256(password.encode()).hexdigest() == hash

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user and return user data"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(password, user[2]):
        return {
            'id': user[0],
            'username': user[1],
            'role': user[3]
        }
    return None

def get_fmea_entries(search: str = '', risk_filter: str = '', status_filter: str = '') -> List[Dict[str, Any]]:
    """Get FMEA entries with optional filters"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    query = '''
        SELECT id, function, failure_mode, failure_effect, severity, failure_cause,
               occurrence, test_method, detection, actions, status, created_at, updated_at
        FROM fmea_entries
        WHERE 1=1
    '''
    params = []
    
    if search:
        query += " AND (function LIKE ? OR failure_mode LIKE ? OR failure_cause LIKE ? OR failure_effect LIKE ?)"
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param, search_param])
    
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)
    
    query += " ORDER BY created_at DESC"
    
    cursor.execute(query, params)
    entries = cursor.fetchall()
    conn.close()
    
    result = []
    for entry in entries:
        rpn = entry[4] * entry[6] * entry[8]  # severity * occurrence * detection
        risk_level = 'high' if rpn > 100 else 'medium' if rpn > 50 else 'low'
        
        # Apply risk filter
        if risk_filter and risk_filter != risk_level:
            continue
            
        result.append({
            'id': entry[0],
            'function': entry[1],
            'failure_mode': entry[2],
            'failure_effect': entry[3],
            'severity': entry[4],
            'failure_cause': entry[5],
            'occurrence': entry[6],
            'test_method': entry[7],
            'detection': entry[8],
            'actions': entry[9],
            'status': entry[10],
            'created_at': entry[11],
            'updated_at': entry[12],
            'rpn': rpn,
            'risk_level': risk_level
        })
    
    return result

def add_fmea_entry(entry_data: Dict[str, Any]) -> bool:
    """Add new FMEA entry"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO fmea_entries (function, failure_mode, failure_effect, severity, failure_cause,
                                    occurrence, test_method, detection, actions, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry_data['function'], entry_data['failure_mode'], entry_data['failure_effect'],
            entry_data['severity'], entry_data['failure_cause'], entry_data['occurrence'],
            entry_data['test_method'], entry_data['detection'], entry_data['actions'],
            entry_data['status'], entry_data['created_by']
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Speichern: {str(e)}")
        return False

def update_fmea_entry(entry_id: int, entry_data: Dict[str, Any]) -> bool:
    """Update existing FMEA entry"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE fmea_entries 
            SET function=?, failure_mode=?, failure_effect=?, severity=?, failure_cause=?,
                occurrence=?, test_method=?, detection=?, actions=?, status=?, updated_at=?
            WHERE id=?
        ''', (
            entry_data['function'], entry_data['failure_mode'], entry_data['failure_effect'],
            entry_data['severity'], entry_data['failure_cause'], entry_data['occurrence'],
            entry_data['test_method'], entry_data['detection'], entry_data['actions'],
            entry_data['status'], datetime.now().isoformat(), entry_id
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Aktualisieren: {str(e)}")
        return False

def delete_fmea_entry(entry_id: int) -> bool:
    """Delete FMEA entry"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fmea_entries WHERE id=?", (entry_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Löschen: {str(e)}")
        return False

def get_actions() -> List[Dict[str, Any]]:
    """Get all actions with extended fields"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT a.id, a.title, a.description, a.assigned_to, a.priority, a.status, 
               a.due_date, a.fmea_entry_id, a.created_at, f.function,
               a.empfohlene_abstellmassnahmen, a.ausfuehrung_durch, a.verbesserter_zustand,
               a.verantwortlicher_name, a.datum_bis, a.getroffene_massnahme,
               a.umgesetzt_am, a.umgesetzt_durch, a.neue_auftretenswahrscheinlichkeit,
               a.neues_auftreten, a.neue_entdeckung, a.neue_rpz
        FROM actions a
        LEFT JOIN fmea_entries f ON a.fmea_entry_id = f.id
        ORDER BY a.created_at DESC
    ''')
    
    actions = cursor.fetchall()
    conn.close()
    
    return [{
        'id': action[0],
        'title': action[1],
        'description': action[2],
        'assigned_to': action[3],
        'priority': action[4],
        'status': action[5],
        'due_date': action[6],
        'fmea_entry_id': action[7],
        'created_at': action[8],
        'fmea_function': action[9],
        'empfohlene_abstellmassnahmen': action[10],
        'ausfuehrung_durch': action[11],
        'verbesserter_zustand': action[12],
        'verantwortlicher_name': action[13],
        'datum_bis': action[14],
        'getroffene_massnahme': action[15],
        'umgesetzt_am': action[16],
        'umgesetzt_durch': action[17],
        'neue_auftretenswahrscheinlichkeit': action[18],
        'neues_auftreten': action[19],
        'neue_entdeckung': action[20],
        'neue_rpz': action[21]
    } for action in actions]

def add_action(action_data: Dict[str, Any]) -> bool:
    """Add new action with extended fields"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Calculate new RPZ if A, B, E values are provided
        neue_rpz = None
        if (action_data.get('neue_auftretenswahrscheinlichkeit') and 
            action_data.get('neues_auftreten') and 
            action_data.get('neue_entdeckung')):
            neue_rpz = (action_data['neue_auftretenswahrscheinlichkeit'] * 
                       action_data['neues_auftreten'] * 
                       action_data['neue_entdeckung'])
        
        cursor.execute('''
            INSERT INTO actions (title, description, assigned_to, priority, status, due_date, 
                               fmea_entry_id, created_by, empfohlene_abstellmassnahmen, 
                               ausfuehrung_durch, verbesserter_zustand, verantwortlicher_name,
                               datum_bis, getroffene_massnahme, umgesetzt_am, umgesetzt_durch,
                               neue_auftretenswahrscheinlichkeit, neues_auftreten, 
                               neue_entdeckung, neue_rpz)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action_data['title'], action_data['description'], action_data['assigned_to'],
            action_data['priority'], action_data['status'], action_data['due_date'],
            action_data['fmea_entry_id'], action_data['created_by'],
            action_data.get('empfohlene_abstellmassnahmen'),
            action_data.get('ausfuehrung_durch'), action_data.get('verbesserter_zustand'),
            action_data.get('verantwortlicher_name'), action_data.get('datum_bis'),
            action_data.get('getroffene_massnahme'), action_data.get('umgesetzt_am'),
            action_data.get('umgesetzt_durch'), action_data.get('neue_auftretenswahrscheinlichkeit'),
            action_data.get('neues_auftreten'), action_data.get('neue_entdeckung'), neue_rpz
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Speichern der Maßnahme: {str(e)}")
        return False

def update_action(action_id: int, action_data: Dict[str, Any]) -> bool:
    """Update existing action with extended fields"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Calculate new RPZ if A, B, E values are provided
        neue_rpz = None
        if (action_data.get('neue_auftretenswahrscheinlichkeit') and 
            action_data.get('neues_auftreten') and 
            action_data.get('neue_entdeckung')):
            neue_rpz = (action_data['neue_auftretenswahrscheinlichkeit'] * 
                       action_data['neues_auftreten'] * 
                       action_data['neue_entdeckung'])
        
        cursor.execute('''
            UPDATE actions 
            SET title=?, description=?, assigned_to=?, priority=?, status=?, due_date=?,
                empfohlene_abstellmassnahmen=?, ausfuehrung_durch=?, verbesserter_zustand=?,
                verantwortlicher_name=?, datum_bis=?, getroffene_massnahme=?,
                umgesetzt_am=?, umgesetzt_durch=?, neue_auftretenswahrscheinlichkeit=?,
                neues_auftreten=?, neue_entdeckung=?, neue_rpz=?, updated_at=?
            WHERE id=?
        ''', (
            action_data['title'], action_data['description'], action_data['assigned_to'],
            action_data['priority'], action_data['status'], action_data['due_date'],
            action_data.get('empfohlene_abstellmassnahmen'),
            action_data.get('ausfuehrung_durch'), action_data.get('verbesserter_zustand'),
            action_data.get('verantwortlicher_name'), action_data.get('datum_bis'),
            action_data.get('getroffene_massnahme'), action_data.get('umgesetzt_am'),
            action_data.get('umgesetzt_durch'), action_data.get('neue_auftretenswahrscheinlichkeit'),
            action_data.get('neues_auftreten'), action_data.get('neue_entdeckung'), 
            neue_rpz, datetime.now().isoformat(), action_id
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Aktualisieren der Maßnahme: {str(e)}")
        return False

def delete_action(action_id: int) -> bool:
    """Delete action"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM actions WHERE id=?", (action_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Löschen der Maßnahme: {str(e)}")
        return False

def get_statistics() -> Dict[str, Any]:
    """Get dashboard statistics"""
    entries = get_fmea_entries()
    
    total = len(entries)
    high_risk = len([e for e in entries if e['rpn'] > 100])
    medium_risk = len([e for e in entries if 50 <= e['rpn'] <= 100])
    low_risk = len([e for e in entries if e['rpn'] < 50])
    
    open_count = len([e for e in entries if e['status'] == 'Offen'])
    in_progress = len([e for e in entries if e['status'] == 'In Bearbeitung'])
    completed = len([e for e in entries if e['status'] == 'Abgeschlossen'])
    
    return {
        'total': total,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'open': open_count,
        'in_progress': in_progress,
        'completed': completed,
        'completion_rate': round((completed / total * 100) if total > 0 else 0, 1)
    }

def export_to_csv(entries: List[Dict[str, Any]]) -> str:
    """Export FMEA entries to CSV"""
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
            entry['function'],
            entry['failure_mode'],
            entry['failure_effect'],
            entry['severity'],
            entry['failure_cause'],
            entry['occurrence'],
            entry['test_method'],
            entry['detection'],
            entry['rpn'],
            entry['actions'] or '',
            entry['status'],
            entry['created_at']
        ])
    
    return output.getvalue()

def main():
    st.set_page_config(
        page_title="FMEA Management System",
        #page_icon="⚠️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize database
    init_db()
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user' not in st.session_state:
        st.session_state.user = None
    
    # Authentication
    if not st.session_state.authenticated:
        st.title("🔐 FMEA System - Anmeldung")
        
        with st.form("login_form"):
            username = st.text_input("Benutzername")
            password = st.text_input("Passwort", type="password")
            submit = st.form_submit_button("Anmelden")
            
            if submit:
                user = authenticate_user(username, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.user = user
                    st.success(f"Willkommen, {user['username']}!")
                    st.rerun()
                else:
                    st.error("Ungültige Anmeldedaten!")
        
        st.info("Demo-Zugangsdaten: admin/admin123 oder user/user123")
        return
    
    # Main application
    st.title("FMEA Management System")
    
    # Sidebar
    with st.sidebar:
        st.write(f"Eingeloggt als: **{st.session_state.user['username']}** ({st.session_state.user['role']})")
        
        if st.button("Abmelden"):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.rerun()
        
        st.divider()
        
        menu_options = ["Dashboard", "FMEA Eintrag hinzufügen"]
        if st.session_state.user['role'] == 'admin':
            menu_options.append("Maßnahmen verwalten")
        
        selected_page = st.selectbox("Navigation", menu_options)
    
    # Dashboard
    if selected_page == "Dashboard":
        st.header("📊 Dashboard")
        
        # Statistics
        stats = get_statistics()
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Gesamt Einträge", stats['total'])
        with col2:
            st.metric("Hohe Risiken", stats['high_risk'])
        with col3:
            st.metric("Offen", stats['open'])
        with col4:
            st.metric("Abschlussrate", f"{stats['completion_rate']}%")
        
        # Filters
        st.subheader("Filter")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            search = st.text_input("Suche", key="search")
        with col2:
            risk_filter = st.selectbox("Risiko", ["", "high", "medium", "low"], key="risk_filter")
        with col3:
            status_filter = st.selectbox("Status", ["", "Offen", "In Bearbeitung", "Abgeschlossen"], key="status_filter")
        with col4:
            if st.button("Filter anwenden"):
                st.rerun()
        
        # Get filtered entries
        entries = get_fmea_entries(search, risk_filter, status_filter)
        
        # Export button
        if entries:
            csv_data = export_to_csv(entries)
            st.download_button(
                label="📥 Als CSV exportieren",
                data=csv_data,
                file_name=f"FMEA_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        # Display entries
        st.subheader(f"FMEA Einträge ({len(entries)})")
        
        if entries:
            for entry in entries:
                with st.expander(f"🔧 {entry['function']} - {entry['failure_mode']} (RPN: {entry['rpn']})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Fehlerfolge:** {entry['failure_effect']}")
                        st.write(f"**Fehlerursache:** {entry['failure_cause']}")
                        st.write(f"**Prüfmaßnahme:** {entry['test_method']}")
                        st.write(f"**Maßnahmen:** {entry['actions'] or 'Keine'}")
                    
                    with col2:
                        st.write(f"**Auftretenswahrscheinlichkeit:** {entry['severity']}")
                        st.write(f"**Auftreten:** {entry['occurrence']}")
                        st.write(f"**Entdeckung:** {entry['detection']}")
                        st.write(f"**RPN:** {entry['rpn']}")
                        
                        # Risk level badge
                        if entry['risk_level'] == 'high':
                            st.error(f"🔴 Hohes Risiko")
                        elif entry['risk_level'] == 'medium':
                            st.warning(f"🟡 Mittleres Risiko")
                        else:
                            st.success(f"🟢 Niedriges Risiko")
                        
                        st.write(f"**Status:** {entry['status']}")
                    
                    # Action buttons
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if st.button(f"✏️ Bearbeiten", key=f"edit_{entry['id']}"):
                            st.session_state.edit_entry = entry
                    with col2:
                        if st.session_state.user['role'] == 'admin':
                            if st.button(f"🗑️ Löschen", key=f"delete_{entry['id']}"):
                                if delete_fmea_entry(entry['id']):
                                    st.success("Eintrag gelöscht!")
                                    st.rerun()
                    with col3:
                        st.write(f"Erstellt: {entry['created_at'][:16]}")
        else:
            st.info("Keine Einträge gefunden.")
        
        # Edit form
        if 'edit_entry' in st.session_state:
            st.subheader("✏️ Eintrag bearbeiten")
            entry = st.session_state.edit_entry
            
            with st.form("edit_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    function = st.text_input("Funktion", value=entry['function'])
                    failure_mode = st.text_input("Fehlerart", value=entry['failure_mode'])
                    failure_effect = st.text_area("Fehlerfolge", value=entry['failure_effect'])
                    severity = st.slider("Auftretenswahrscheinlichkeit", 1, 10, entry['severity'])
                    failure_cause = st.text_area("Fehlerursache", value=entry['failure_cause'])
                
                with col2:
                    occurrence = st.slider("Auftreten", 1, 10, entry['occurrence'])
                    test_method = st.text_input("Prüfmaßnahme", value=entry['test_method'])
                    detection = st.slider("Entdeckung", 1, 10, entry['detection'])
                    actions = st.text_area("Maßnahmen", value=entry['actions'] or '')
                    status = st.selectbox("Status", ["Offen", "In Bearbeitung", "Abgeschlossen"], 
                                        index=["Offen", "In Bearbeitung", "Abgeschlossen"].index(entry['status']))
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("💾 Speichern"):
                        entry_data = {
                            'function': function,
                            'failure_mode': failure_mode,
                            'failure_effect': failure_effect,
                            'severity': severity,
                            'failure_cause': failure_cause,
                            'occurrence': occurrence,
                            'test_method': test_method,
                            'detection': detection,
                            'actions': actions,
                            'status': status
                        }
                        
                        if update_fmea_entry(entry['id'], entry_data):
