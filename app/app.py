import os
from flask import Flask, render_template, request, redirect, session, flash
from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

def write_log(username, new_password):
    log_file = os.getenv('LOG_FILE')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, 'a') as f:
        f.write(f"User: {username}, New Password: {new_password}\n")

def ad_auth(username, password):
    server = Server(os.getenv('AD_SERVER'), get_info=ALL)
    user_dn = f"CN={username},{os.getenv('DOMAIN_DN')}"
    try:
        with Connection(server, user=user_dn, password=password) as conn:
            return conn.bind()
    except:
        return False

def change_ad_password(username, new_password):
    server = Server(os.getenv('AD_SERVER'), get_info=ALL)
    admin_user = f"CN={os.getenv('ADMIN_USER')},{os.getenv('DOMAIN_DN')}"
    
    try:
        with Connection(server, user=admin_user, password=os.getenv('ADMIN_PASSWORD')) as conn:
            user_dn = f"CN={username},{os.getenv('DOMAIN_DN')}"
            unicode_password = f'"{new_password}"'.encode('utf-16-le')
            changes = {'unicodePwd': [(ldap3.MODIFY_REPLACE, [unicode_password])]}
            return conn.modify(user_dn, changes)
    except Exception as e:
        print(f"Error changing password: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if ad_auth(username, password):
            session['username'] = username
            return redirect('/change_password')
        else:
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