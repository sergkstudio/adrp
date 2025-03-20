import os
import logging
from ldap3 import Server, Connection, MODIFY_REPLACE, ALL, core
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Настройка логгера
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

def log_credentials(username, password):
    logging.warning(f"Login attempt - Username: {username}")

def change_ad_password(username, new_password):
    try:
        server = Server(os.getenv('AD_SERVER'), use_ssl=False, get_info=ALL)
        admin_conn = Connection(
            server,
            user=os.getenv('AD_ADMIN_USER'),
            password=os.getenv('AD_ADMIN_PASSWORD'),
            auto_bind=True
        )
        logging.info(f"Admin connection established: {admin_conn}")

        user_dn = f"CN={username},CN=Users,{os.getenv('AD_BASE_DN')}"
        logging.debug(f"Trying to modify password for DN: {user_dn}")

        unicode_pass = f'"{new_password}"'.encode('utf-16-le')
        result = admin_conn.modify(
            user_dn,
            {'unicodePwd': [(MODIFY_REPLACE, [unicode_pass])}
        )
        
        if admin_conn.result['result'] == 0:
            logging.info(f"Password changed successfully for {username}")
            return True
        
        logging.error(f"Password change failed: {admin_conn.result}")
        return False

    except core.exceptions.LDAPInvalidCredentialsResult:
        logging.error("Invalid admin credentials")
        return False
    except Exception as e:
        logging.exception("Error in change_ad_password")
        return False
    finally:
        if admin_conn:
            admin_conn.unbind()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        log_credentials(username, password)
        
        try:
            server = Server(os.getenv('AD_SERVER'), use_ssl=False)
            user_conn = Connection(
                server,
                user=f"{os.getenv('AD_DOMAIN')}\\{username}",
                password=password,
                auto_bind=True
            )
            logging.info(f"User authenticated: {username}")
            user_conn.unbind()
            return redirect(url_for('change_password', username=username))
            
        except core.exceptions.LDAPInvalidCredentialsResult:
            logging.warning(f"Invalid credentials for {username}")
            flash("Invalid username or password", "error")
        except Exception as e:
            logging.exception("Login error")
            flash(f"Error: {str(e)}", "error")
        
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    username = request.args.get('username')
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        if change_ad_password(username, new_password):
            flash("Password changed successfully", "success")
            return redirect(url_for('login'))
        
        flash("Password change failed. Contact administrator.", "error")
        return redirect(url_for('login'))
    
    return render_template('change_password.html', username=username)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)