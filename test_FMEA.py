import unittest
from unittest.mock import patch, MagicMock
from app import app, db, User, FMEAEntry
from flask import session

class FMEATestCase(unittest.TestCase):
    def setUp(self):
        # Setup the Flask test client
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()

        # Create tables in in-memory DB
        with app.app_context():
            db.create_all()

    def tearDown(self):
        # Drop all tables after each test
        with app.app_context():
            db.drop_all()

    def test_login_success(self):
        # Setup: add a test user
        with app.app_context():
            user = User(username="testuser", role="user")
            user.set_password("password123")
            db.session.add(user)
            db.session.commit()

        # Act
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'password123'
        }, follow_redirects=True)

        # Assert
        self.assertIn(b'Willkommen, testuser!', response.data)
        self.assertEqual(response.status_code, 200)

    def test_login_failure(self):
        response = self.client.post('/login', data={
            'username': 'fakeuser',
            'password': 'wrongpass'
        }, follow_redirects=True)

        self.assertIn(b'Ung\xc3\xbcltige Anmeldedaten', response.data)  # Ungültige Anmeldedaten
        self.assertEqual(response.status_code, 200)

    @patch('app.FMEAEntry.query')
    def test_dashboard_with_mock(self, mock_query):
        # Setup: simulate a logged-in session
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'

        mock_entry = MagicMock()
        mock_entry.rpn = 120
        mock_entry.status = 'Offen'
        mock_entry.to_dict.return_value = {}
        mock_query.order_by.return_value.all.return_value = [mock_entry]

        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'FMEA', response.data)

    @patch('app.db.session')
    def test_add_entry_post(self, mock_session):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'test'
            sess['role'] = 'user'

        data = {
            'function': 'Test Function',
            'failure_mode': 'Mode',
            'failure_effect': 'Effect',
            'severity': '5',
            'failure_cause': 'Cause',
            'occurrence': '3',
            'test_method': 'Test',
            'detection': '4',
            'actions': 'None',
            'status': 'Offen'
        }

        response = self.client.post('/add_entry', data=data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'FMEA-Eintrag erfolgreich hinzugef', response.data)

        self.assertTrue(mock_session.add.called)
        self.assertTrue(mock_session.commit.called)


if __name__ == '__main__':
    unittest.main()