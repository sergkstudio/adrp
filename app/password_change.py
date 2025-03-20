from flask import Flask, redirect, url_for, session, request, render_template, flash
from auth import authenticate_user, is_admin_user
from password_change import change_password, admin_change_password
import os
import logging

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key_here')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if authenticate_user(username, password):
            session['username'] = username
            session['is_admin'] = is_admin_user(username)  # Проверка прав администратора
            return redirect(url_for('profile'))
        else:
            flash('Неверные учетные данные', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('profile.html', 
                         username=session['username'],
                         is_admin=session.get('is_admin', False))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        username = session['username']
        
        success, message = change_password(username, new_password, old_password)
        flash(message, 'success' if success else 'error')
        return redirect(url_for('change_password_route'))
    
    return render_template('user_change_password.html')

@app.route('/admin/change-password', methods=['GET', 'POST'])
def admin_change_password_route():
    if not session.get('is_admin'):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        target_username = request.form.get('target_username')
        new_password = request.form.get('new_password')
        
        success, message = admin_change_password(target_username, new_password)
        flash(message, 'success' if success else 'error')
        return redirect(url_for('admin_change_password_route'))
    
    return render_template('admin_change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)