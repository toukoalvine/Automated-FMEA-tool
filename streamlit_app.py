import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import pandas as pd
import os

# Database Setup
Base = declarative_base()

# Use environment variable for database URL or default to SQLite
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///fmea.db')
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# Models
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=False)
    role = Column(String(20), default='user')
    created_at = Column(DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FMEAEntry(Base):
    __tablename__ = 'fmea_entry'
    id = Column(Integer, primary_key=True)
    function = Column(String(200), nullable=False)
    failure_mode = Column(String(200), nullable=False)
    failure_effect = Column(Text, nullable=False)
    severity = Column(Integer, nullable=False)
    failure_cause = Column(Text, nullable=False)
    occurrence = Column(Integer, nullable=False)
    test_method = Column(String(200), nullable=False)
    detection = Column(Integer, nullable=False)
    actions = Column(Text)
    status = Column(String(50), default='Offen')
    created_by = Column(Integer, ForeignKey('user.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def rpn(self):
        return self.severity * self.occurrence * self.detection

    @property
    def risk_level(self):
        rpn = self.rpn
        if rpn > 100:
            return 'Hoch'
        elif rpn > 50:
            return 'Mittel'
        else:
            return 'Niedrig'

# Create tables
Base.metadata.create_all(engine)

def get_session():
    """Get database session"""
    return Session()

def create_default_user():
    """Create default admin user if no users exist"""
    session = get_session()
    try:
        if session.query(User).count() == 0:
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin123')
            session.add(admin_user)
            session.commit()
            st.info("Default admin user created: admin/admin123")
    except Exception as e:
        st.error(f"Error creating default user: {e}")
    finally:
        session.close()

# Streamlit UI
st.set_page_config(page_title="FMEA Dashboard", layout="wide")
st.title("🔧 FMEA Web App")

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ''
    st.session_state.user_id = None

# Create default user
create_default_user()

# Login Section
if not st.session_state.logged_in:
    st.subheader("🔐 Anmeldung")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        username = st.text_input("Benutzername")
        password = st.text_input("Passwort", type="password")
        
        if st.button("Einloggen", type="primary"):
            session = get_session()
            try:
                user = session.query(User).filter_by(username=username).first()
                if user and user.check_password(password):
                    st.session_state.logged_in = True
                    st.session_state.username = user.username
                    st.session_state.user_id = user.id
                    st.success(f"Willkommen, {user.username}!")
                    st.rerun()
                else:
                    st.error("Ungültige Anmeldedaten")
            except Exception as e:
                st.error(f"Fehler beim Anmelden: {e}")
            finally:
                session.close()
    
    with col2:
        st.info("**Standard-Anmeldedaten:**\n\nBenutzername: `admin`\nPasswort: `admin123`")

else:
    # Sidebar for logged-in user
    with st.sidebar:
        st.success(f"✅ Eingeloggt als {st.session_state.username}")
        if st.button("Abmelden"):
            st.session_state.logged_in = False
            st.session_state.username = ''
            st.session_state.user_id = None
            st.rerun()

    # Main content tabs
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "➕ Eintrag hinzufügen", "📈 Statistiken"])

    with tab1:
        st.subheader("FMEA Einträge")
        
        session = get_session()
        try:
            entries = session.query(FMEAEntry).order_by(FMEAEntry.created_at.desc()).all()
            
            if entries:
                # Filters
                col1, col2, col3 = st.columns(3)
                with col1:
                    status_filter = st.selectbox("Status filtern", ["Alle", "Offen", "In Bearbeitung", "Abgeschlossen"])
                with col2:
                    risk_filter = st.selectbox("Risiko filtern", ["Alle", "Hoch", "Mittel", "Niedrig"])
                with col3:
                    min_rpn = st.number_input("Min. RPN", min_value=0, value=0)

                # Prepare data
                data = []
                for e in entries:
                    # Apply filters
                    if status_filter != "Alle" and e.status != status_filter:
                        continue
                    if risk_filter != "Alle" and e.risk_level != risk_filter:
                        continue
                    if e.rpn < min_rpn:
                        continue
                    
                    data.append({
                        "ID": e.id,
                        "Funktion": e.function,
                        "Fehlerart": e.failure_mode[:50] + "..." if len(e.failure_mode) > 50 else e.failure_mode,
                        "Schwere": e.severity,
                        "Auftreten": e.occurrence,
                        "Entdeckung": e.detection,
                        "RPN": e.rpn,
                        "Risikolevel": e.risk_level,
                        "Status": e.status,
                        "Erstellt am": e.created_at.strftime("%d.%m.%Y")
                    })

                if data:
                    df = pd.DataFrame(data)
                    
                    # Color coding for risk levels
                    def color_risk_level(val):
                        if val == 'Hoch':
                            return 'color: red; font-weight: bold'
                        elif val == 'Mittel':
                            return 'color: orange; font-weight: bold'
                        else:
                            return 'color: green'
                    
                    styled_df = df.style.applymap(color_risk_level, subset=['Risikolevel'])
                    st.dataframe(styled_df, use_container_width=True)
                    
                    # Export functionality
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="📥 CSV herunterladen",
                        data=csv,
                        file_name=f"fmea_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                else:
                    st.info("Keine Einträge entsprechen den Filterkriterien.")
            else:
                st.info("Noch keine FMEA-Einträge vorhanden.")
        
        except Exception as e:
            st.error(f"Fehler beim Laden der Einträge: {e}")
        finally:
            session.close()

    with tab2:
        st.subheader("Neuen FMEA-Eintrag hinzufügen")
        
        with st.form("fmea_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                function = st.text_input("Funktion *", help="Beschreibung der Funktion oder des Prozesses")
                failure_mode = st.text_input("Fehlerart *", help="Art des möglichen Fehlers")
                failure_effect = st.text_area("Fehlerfolge *", help="Auswirkungen des Fehlers")
                severity = st.slider("Schwere (1-10) *", 1, 10, 5, help="1=geringfügig, 10=katastrophal")
                
            with col2:
                failure_cause = st.text_area("Fehlerursache *", help="Mögliche Ursachen des Fehlers")
                occurrence = st.slider("Auftretenswahrscheinlichkeit (1-10) *", 1, 10, 5, help="1=unwahrscheinlich, 10=sehr wahrscheinlich")
                test_method = st.text_input("Prüfmaßnahme *", help="Methode zur Fehlererkennung")
                detection = st.slider("Entdeckungswahrscheinlichkeit (1-10) *", 1, 10, 5, help="1=sicher erkannt, 10=nicht erkannt")
            
            actions = st.text_area("Maßnahmen", help="Empfohlene Abhilfemaßnahmen")
            status = st.selectbox("Status", ["Offen", "In Bearbeitung", "Abgeschlossen"])
            
            # Calculate RPN in real-time
            rpn = severity * occurrence * detection
            risk_level = "Hoch" if rpn > 100 else "Mittel" if rpn > 50 else "Niedrig"
            
            st.info(f"**Berechnet:** RPN = {rpn} (Risikolevel: {risk_level})")
            
            submitted = st.form_submit_button("💾 Speichern", type="primary")

            if submitted:
                if all([function, failure_mode, failure_effect, failure_cause, test_method]):
                    session = get_session()
                    try:
                        entry = FMEAEntry(
                            function=function,
                            failure_mode=failure_mode,
                            failure_effect=failure_effect,
                            severity=severity,
                            failure_cause=failure_cause,
                            occurrence=occurrence,
                            test_method=test_method,
                            detection=detection,
                            actions=actions,
                            status=status,
                            created_by=st.session_state.user_id
                        )
                        session.add(entry)
                        session.commit()
                        st.success("✅ Eintrag erfolgreich gespeichert!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Fehler beim Speichern: {e}")
                    finally:
                        session.close()
                else:
                    st.error("Bitte füllen Sie alle Pflichtfelder (*) aus.")

    with tab3:
        st.subheader("📈 FMEA Statistiken")
        
        session = get_session()
        try:
            entries = session.query(FMEAEntry).all()
            
            if entries:
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Gesamt Einträge", len(entries))
                
                with col2:
                    high_risk = len([e for e in entries if e.risk_level == "Hoch"])
                    st.metric("Hohes Risiko", high_risk)
                
                with col3:
                    avg_rpn = sum(e.rpn for e in entries) / len(entries)
                    st.metric("Durchschn. RPN", f"{avg_rpn:.1f}")
                
                with col4:
                    open_entries = len([e for e in entries if e.status == "Offen"])
                    st.metric("Offene Einträge", open_entries)
                
                # Charts
                col1, col2 = st.columns(2)
                
                with col1:
                    # Risk level distribution
                    risk_counts = {"Hoch": 0, "Mittel": 0, "Niedrig": 0}
                    for entry in entries:
                        risk_counts[entry.risk_level] += 1
                    
                    chart_data = pd.DataFrame(list(risk_counts.items()), columns=['Risikolevel', 'Anzahl'])
                    st.bar_chart(chart_data.set_index('Risikolevel'))
                
                with col2:
                    # Status distribution
                    status_counts = {}
                    for entry in entries:
                        status_counts[entry.status] = status_counts.get(entry.status, 0) + 1
                    
                    chart_data = pd.DataFrame(list(status_counts.items()), columns=['Status', 'Anzahl'])
                    st.bar_chart(chart_data.set_index('Status'))
            
            else:
                st.info("Keine Daten für Statistiken verfügbar.")
        
        except Exception as e:
            st.error(f"Fehler beim Laden der Statistiken: {e}")
        finally:
            session.close()
