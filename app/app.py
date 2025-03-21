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

def ad_auth(username, password):
    server_address = os.getenv('AD_SERVER')
    domain_dn = os.getenv('DOMAIN_DN')
    logger.debug(f"Attempting authentication for: {username}")
    logger.debug(f"AD_SERVER: {server_address}, DOMAIN_DN: {domain_dn}")

    try:
        server = Server(server_address, get_info=ALL)
        user_dn = f"CN={username},{domain_dn}"
        logger.debug(f"Trying to bind with DN: {user_dn}")

        conn = Connection(server, user=user_dn, password=password)
        conn.start_tls()
        if conn.result['result'] == 0:
            logger.info(f"Successful authentication for: {username}")
            return True
        logger.error(f"Authentication failed for: {username}. Code: {conn.result['result']}")
        return False
    except Exception as e:
        logger.error(f"Authentication error for {username}: {str(e)}", exc_info=True)
        return False
    finally:
        if 'conn' in locals() and conn.bound:
            conn.unbind()

def change_ad_password(username, new_password):
    server_address = os.getenv('AD_SERVER')
    domain_dn = os.getenv('DOMAIN_DN')
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')

    logger.debug(f"Attempting password change for: {username}")
    
    try:
        server = Server(server_address)
        admin_dn = f"CN={admin_user},{domain_dn}"
        user_dn = f"CN={username},{domain_dn}"
        
        logger.debug(f"Connecting with admin DN: {admin_dn}")
        
        conn = Connection(server, user=admin_dn, password=admin_password)
        conn.start_tls()
        
        if not conn.bind():
            logger.error(f"Bind failed: {conn.result}")
            return False

        logger.debug(f"Connected as admin: {admin_dn}")
        
        unicode_password = f'"{new_password}"'.encode('utf-16-le')
        # Исправлено здесь ▼
        changes = {'unicodePwd': [(MODIFY_REPLACE, [unicode_password])]}
        
        logger.debug(f"Attempting password modification for: {user_dn}")
        
        if conn.modify(user_dn, changes):
            logger.info(f"Password changed successfully for: {username}")
            return True
        
        logger.error(f"Password change failed for: {username}. Response: {conn.result}")
        return False
            
    except Exception as e:
        logger.error(f"Password change error for {username}: {str(e)}", exc_info=True)
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
            session.pop('username')
            flash('Password changed successfully')
            return redirect('/')
        else:
            flash('Failed to change password')
    
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)