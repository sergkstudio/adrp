from flask import Flask, redirect, url_for, session, request, render_template
from auth import authenticate_user
from password_change import change_password

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('change_password'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        username = session['username']
        
        if change_password(username, new_password, old_password):
            return "Password changed successfully"
        else:
            return "Failed to change password", 400
    
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)