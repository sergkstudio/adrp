import os
import logging
from logging.handlers import RotatingFileHandler
import ldap3
from flask import Flask, render_template, request, redirect, session, flash
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, Tls
from dotenv import load_dotenv

load_dotenv()

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        RotatingFileHandler('logs/app.log', maxBytes=1024*1024, backupCount=10),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Проверка обязательных переменных окружения
required_env_vars = ['AD_SERVER', 'ADMIN_USER', 'ADMIN_PASSWORD', 'DOMAIN_DN', 'LOG_FILE']
for var in required_env_vars:
    if not os.getenv(var):
        logger.error(f"Required environment variable {var} is missing")
        raise EnvironmentError(f"Required environment variable {var} is missing")

app = Flask(__name__)
app.secret_key = os.urandom(24)

def write_log(username, new_password):
    log_file = os.getenv('LOG_FILE')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, 'a') as f:
        f.write(f"User: {username}, New Password: {new_password}\n")
    logger.info(f"Password changed for user: {username}")

def get_user_dn(username):
    """Получает distinguishedName пользователя по sAMAccountName"""
    server_address = os.getenv('AD_SERVER')
    domain_dn = os.getenv('DOMAIN_DN')
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')

    try:
        server = Server(server_address)
        conn = Connection(server, user=f"{admin_user}@{domain_dn}", password=admin_password, auto_bind=True)
        
        conn.search(domain_dn, f"(sAMAccountName={username})", attributes=['distinguishedName'])
        
        if conn.entries:
            return conn.entries[0].distinguishedName.value
        else:
            logger.error(f"User {username} not found in AD")
            return None
    except Exception as e:
        logger.error(f"Error retrieving DN for {username}: {str(e)}", exc_info=True)
        return None

def ad_auth(username, password):
    """Аутентификация пользователя через sAMAccountName"""
    user_dn = get_user_dn(username)
    if not user_dn:
        return False

    try:
        server = Server(os.getenv('AD_SERVER'))
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        logger.info(f"Successful authentication for: {username}")
        return True
    except Exception as e:
        logger.error(f"Authentication failed for {username}: {str(e)}")
        return False

def change_ad_password(username, new_password):
    """Смена пароля через sAMAccountName"""
    user_dn = get_user_dn(username)
    if not user_dn:
        return False

    server_address = os.getenv('AD_SERVER')
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')

    try:
        server = Server(server_address)
        conn = Connection(server, user=f"{admin_user}@{os.getenv('DOMAIN_DN')}", password=admin_password, auto_bind=True)

        unicode_password = f'"{new_password}"'.encode('utf-16-le')
        changes = {'unicodePwd': [(MODIFY_REPLACE, [unicode_password])]}

        if conn.modify(user_dn, changes):
            logger.info(f"Password changed successfully for: {username}")
            return True

        logger.error(f"Password change failed for: {username}. Response: {conn.result}")
        return False
    except Exception as e:
        logger.error(f"Password change error for {username}: {str(e)}", exc_info=True)
        return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        logger.info(f"Login attempt for user: {username}")
        
        if ad_auth(username, password):
            session['username'] = username
            return redirect('/change_password')
        else:
            logger.warning(f"Invalid credentials for user: {username}")
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect('/')
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect('/change_password')
        
        if change_ad_password(session['username'], new_password):
            write_log(session['username'], new_password)
            flash('Password changed successfully')
            return redirect('/success')
        else:
            flash('Failed to change password')
    
    return render_template('change_password.html')

@app.route('/success')
def success():
    if 'username' not in session:
        return redirect('/')
    username = session.pop('username')
    return render_template('success.html', username=username)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)