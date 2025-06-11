import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import pandas as pd

# Database Setup
Base = declarative_base()
engine = create_engine('sqlite:///fmea.db')
Session = sessionmaker(bind=engine)
session = Session()

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
    updated_at = Column(DateTime, default=datetime.utcnow)

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

Base.metadata.create_all(engine)

# Streamlit UI
st.set_page_config(page_title="FMEA Dashboard", layout="wide")
st.title("FMEA Web App")

# Login State
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ''

# Login
if not st.session_state.logged_in:
    st.subheader("Login")
    username = st.text_input("Benutzername")
    password = st.text_input("Passwort", type="password")
    if st.button("Einloggen"):
        user = session.query(User).filter_by(username=username).first()
        if user and user.check_password(password):
            st.session_state.logged_in = True
            st.session_state.username = user.username
            st.success(f"Willkommen, {user.username}!")
            st.experimental_rerun()
        else:
            st.error("Ungültige Anmeldedaten")

else:
    st.sidebar.success(f"Eingeloggt als {st.session_state.username}")
    if st.sidebar.button("Abmelden"):
        st.session_state.logged_in = False
        st.session_state.username = ''
        st.experimental_rerun()

    tab1, tab2 = st.tabs(["Dashboard", "Eintrag hinzufügen"])

    with tab1:
        st.subheader("FMEA Einträge")
        entries = session.query(FMEAEntry).order_by(FMEAEntry.created_at.desc()).all()

        data = [
            {
                "Funktion": e.function,
                "Fehlerart": e.failure_mode,
                "Fehlerfolge": e.failure_effect,
                "Ursache": e.failure_cause,
                "Prüfmaßnahme": e.test_method,
                "Status": e.status,
                "RPN": e.rpn,
                "Risikolevel": e.risk_level,
                "Erstellt am": e.created_at.strftime("%Y-%m-%d")
            }
            for e in entries
        ]

        df = pd.DataFrame(data)
        st.dataframe(df)

    with tab2:
        st.subheader("Neuen FMEA-Eintrag hinzufügen")
        with st.form("fmea_form"):
            function = st.text_input("Funktion")
            failure_mode = st.text_input("Fehlerart")
            failure_effect = st.text_area("Fehlerfolge")
            severity = st.slider("Schwere (1-10)", 1, 10, 5)
            failure_cause = st.text_area("Fehlerursache")
            occurrence = st.slider("Auftretenswahrscheinlichkeit (1-10)", 1, 10, 5)
            test_method = st.text_input("Prüfmaßnahme")
            detection = st.slider("Entdeckungswahrscheinlichkeit (1-10)", 1, 10, 5)
            actions = st.text_area("Maßnahmen", '')
            status = st.selectbox("Status", ["Offen", "In Bearbeitung", "Abgeschlossen"])
            submitted = st.form_submit_button("Speichern")

            if submitted:
                user = session.query(User).filter_by(username=st.session_state.username).first()
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
                    created_by=user.id
                )
                session.add(entry)
                session.commit()
                st.success("Eintrag erfolgreich gespeichert.")
                st.experimental_rerun()
