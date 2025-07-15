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
    
    # Create Actions table
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
            FOREIGN KEY (fmea_entry_id) REFERENCES fmea_entries (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
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
    """Get all actions"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT a.id, a.title, a.description, a.assigned_to, a.priority, a.status, 
               a.due_date, a.fmea_entry_id, a.created_at, f.function
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
        'fmea_function': action[9]
    } for action in actions]

def add_action(action_data: Dict[str, Any]) -> bool:
    """Add new action"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO actions (title, description, assigned_to, priority, status, due_date, fmea_entry_id, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action_data['title'], action_data['description'], action_data['assigned_to'],
            action_data['priority'], action_data['status'], action_data['due_date'],
            action_data['fmea_entry_id'], action_data['created_by']
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Fehler beim Speichern der Maßnahme: {str(e)}")
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
                            st.success("Eintrag aktualisiert!")
                            del st.session_state.edit_entry
                            st.rerun()
                
                with col2:
                    if st.form_submit_button("❌ Abbrechen"):
                        del st.session_state.edit_entry
                        st.rerun()
    
    # Add FMEA Entry
    elif selected_page == "FMEA Eintrag hinzufügen":
        st.header("➕ Neuen FMEA Eintrag hinzufügen")
        
        with st.form("add_entry_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                function = st.text_input("Funktion *")
                failure_mode = st.text_input("Fehlerart *")
                failure_effect = st.text_area("Fehlerfolge *")
                severity = st.slider("Auftretenswahrscheinlichkeit (1-10)", 1, 10, 5)
                failure_cause = st.text_area("Fehlerursache *")
            
            with col2:
                occurrence = st.slider("Auftreten (1-10)", 1, 10, 5)
                test_method = st.text_input("Prüfmaßnahme *")
                detection = st.slider("Entdeckung (1-10)", 1, 10, 5)
                actions = st.text_area("Maßnahmen")
                status = st.selectbox("Status", ["Offen", "In Bearbeitung", "Abgeschlossen"])
            
            # Show calculated RPN
            rpn = severity * occurrence * detection
            risk_level = 'Hoch' if rpn > 100 else 'Mittel' if rpn > 50 else 'Niedrig'
            st.info(f"Berechnete RPN: {rpn} (Risiko: {risk_level})")
            
            if st.form_submit_button("💾 Eintrag speichern"):
                if function and failure_mode and failure_effect and failure_cause and test_method:
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
                        'status': status,
                        'created_by': st.session_state.user['id']
                    }
                    
                    if add_fmea_entry(entry_data):
                        st.success("FMEA-Eintrag erfolgreich hinzugefügt!")
                        st.rerun()
                else:
                    st.error("Bitte füllen Sie alle Pflichtfelder (*) aus.")
    
    # Manage Actions (Admin only)
    elif selected_page == "Maßnahmen verwalten" and st.session_state.user['role'] == 'admin':
        st.header("📋 Maßnahmen verwalten")
        
        # Add new action
        with st.expander("➕ Neue Maßnahme hinzufügen"):
            with st.form("add_action_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    title = st.text_input("Titel *")
                    description = st.text_area("Beschreibung")
                    assigned_to = st.text_input("Zugewiesen an")
                
                with col2:
                    priority = st.selectbox("Priorität", ["Niedrig", "Mittel", "Hoch"])
                    action_status = st.selectbox("Status", ["Offen", "In Bearbeitung", "Abgeschlossen"])
                    due_date = st.date_input("Fälligkeitsdatum", value=None)
                
                # FMEA Entry selection
                entries = get_fmea_entries()
                fmea_options = ["Keine Zuordnung"] + [f"{e['id']}: {e['function']} - {e['failure_mode']}" for e in entries]
                fmea_selection = st.selectbox("FMEA Eintrag", fmea_options)
                
                if st.form_submit_button("💾 Maßnahme speichern"):
                    if title:
                        fmea_entry_id = None
                        if fmea_selection != "Keine Zuordnung":
                            fmea_entry_id = int(fmea_selection.split(":")[0])
                        
                        action_data = {
                            'title': title,
                            'description': description,
                            'assigned_to': assigned_to,
                            'priority': priority,
                            'status': action_status,
                            'due_date': due_date.isoformat() if due_date else None,
                            'fmea_entry_id': fmea_entry_id,
                            'created_by': st.session_state.user['id']
                        }
                        
                        if add_action(action_data):
                            st.success("Maßnahme erfolgreich hinzugefügt!")
                            st.rerun()
                    else:
                        st.error("Bitte geben Sie einen Titel ein.")
        
        # Display actions
        actions = get_actions()
        st.subheader(f"Aktuelle Maßnahmen ({len(actions)})")
        
        if actions:
            for action in actions:
                with st.expander(f"📋 {action['title']} - {action['status']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Beschreibung:** {action['description'] or 'Keine'}")
                        st.write(f"**Zugewiesen an:** {action['assigned_to'] or 'Nicht zugewiesen'}")
                        st.write(f"**Priorität:** {action['priority']}")
                    
                    with col2:
                        st.write(f"**Status:** {action['status']}")
                        st.write(f"**Fälligkeitsdatum:** {action['due_date'] or 'Nicht gesetzt'}")
                        st.write(f"**FMEA Eintrag:** {action['fmea_function'] or 'Nicht zugeordnet'}")
                    
                    if st.button(f"🗑️ Löschen", key=f"delete_action_{action['id']}"):
                        if delete_action(action['id']):
                            st.success("Maßnahme gelöscht!")
                            st.rerun()
        else:
            st.info("Keine Maßnahmen vorhanden.")

if __name__ == "__main__":
    main()
