from flask import Flask, redirect, url_for, session, request, render_template, flash
from auth import authenticate_user
from password_change import change_password
import os
import logging

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('change_password_route'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        username = session['username']
        
        success, message = change_password(username, new_password, old_password)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
        return redirect(url_for('change_password_route'))
    
    return render_template('change_password.html')

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)