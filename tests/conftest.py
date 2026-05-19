
import pytest


@pytest.fixture
def vulnerable_repo(tmp_path):
    """Create a fake repo with intentional vulnerabilities for testing."""
    # Python file with hardcoded secret
    py_file = tmp_path / "config.py"
    py_file.write_text('''
API_KEY = "sk-ant-api03-reallyLongFakeKeyThatShouldBeDetected1234567890"
DB_PASSWORD = "super_secret_password_123"
SAFE_VAR = "this is fine"
''')

    # Python file with SQL injection
    sql_file = tmp_path / "database.py"
    sql_file.write_text('''
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def safe_query(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
''')

    # JS file with XSS
    js_file = tmp_path / "app.js"
    js_file.write_text('''
function renderUser(user) {
    document.getElementById("name").innerHTML = user.name;
    document.getElementById("safe").textContent = user.name;
}
''')

    # requirements.txt with known vulnerable package
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==2.0.0\nrequests==2.25.0\n")

    # .env file that shouldn't be committed
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=postgres://user:password@localhost/db\n")

    return tmp_path


@pytest.fixture
def clean_repo(tmp_path):
    """Create a repo with no vulnerabilities."""
    py_file = tmp_path / "app.py"
    py_file.write_text('''
import os

API_KEY = os.environ.get("API_KEY")

def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
''')
    return tmp_path
