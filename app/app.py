import os
import logging
from logging.handlers import RotatingFileHandler
import ldap3
from flask import Flask, render_template, request, redirect, session, flash
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars
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

def get_user_dn(conn, username, domain_dn):
    search_filter = f"(sAMAccountName={escape_filter_chars(username)})"
    conn.search(
        search_base=domain_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['distinguishedName']
    )
    if len(conn.entries) == 0:
        return None
    return conn.entries[0].distinguishedName.value

def ad_auth(username, password):
    server_address = os.getenv('AD_SERVER')
    domain_dn = os.getenv('DOMAIN_DN')
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    try:
        server = Server(server_address, get_info=ALL)
        admin_dn = f"CN={admin_user},{domain_dn}"
        user_dn = f"CN={username},{domain_dn}"
        
        logger.debug(f"Connecting with admin DN: {admin_dn}")
        
        # Подключение администратора для поиска пользователя
        admin_conn = Connection(server, user=admin_dn, password=admin_password)
        admin_conn.start_tls()
        if not admin_conn.bind():
            logger.error(f"Admin bind failed: {admin_conn.result}")
            return False
        
        # Поиск DN пользователя
        user_dn = get_user_dn(admin_conn, username, domain_dn)
        admin_conn.unbind()
        
        if not user_dn:
            logger.error(f"User {username} not found")
            return False
        
        # Проверка пароля пользователя
        user_conn = Connection(server, user=user_dn, password=password)
        if user_conn.bind():
            user_conn.unbind()
            return True
        logger.error(f"User authentication failed: {user_conn.result}")
        return False
        
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}", exc_info=True)
        return False

def change_ad_password(username, new_password):
    server_address = os.getenv('AD_SERVER')
    domain_dn = os.getenv('DOMAIN_DN')
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    try:
        server = Server(server_address, get_info=ALL)
        admin_dn = f"CN={admin_user},{domain_dn}"
        user_dn = f"CN={username},{domain_dn}"
        
        logger.debug(f"Connecting with admin DN: {admin_dn}")
        
        # Подключение администратора для поиска пользователя
        admin_conn = Connection(server, user=admin_dn, password=admin_password)
        admin_conn.start_tls()
        if not admin_conn.bind():
            logger.error(f"Admin bind failed: {admin_conn.result}")
            return False
        
        # Поиск DN пользователя
        user_dn = get_user_dn(admin_conn, username, domain_dn)
        if not user_dn:
            admin_conn.unbind()
            return False
        
        # Смена пароля
        unicode_password = f'"{new_password}"'.encode('utf-16-le')
        changes = {'unicodePwd': [(MODIFY_REPLACE, [unicode_password])]}
        
        if admin_conn.modify(user_dn, changes):
            logger.info(f"Password changed for {username}")
            admin_conn.unbind()
            return True
        logger.error(f"Password change failed: {admin_conn.result}")
        admin_conn.unbind()
        return False
        
    except Exception as e:
        logger.error(f"Password change error: {str(e)}", exc_info=True)
        return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if ad_auth(username, password):
            session['username'] = username
            return redirect('/change_password')
        else:
            flash('Неверные учетные данные')
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect('/')
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Пароли не совпадают')
            return redirect('/change_password')
        
        if change_ad_password(session['username'], new_password):
            write_log(session['username'], new_password)
            flash('Пароль успешно изменен')
            return redirect('/success')
        else:
            flash('Ошибка изменения пароля')
    
    return render_template('change_password.html')

@app.route('/success')
def success():
    if 'username' not in session:
        return redirect('/')
    username = session.pop('username')
    return render_template('success.html', username=username)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)