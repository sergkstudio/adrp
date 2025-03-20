from flask import Blueprint, request, render_template, redirect, url_for
from .auth import authenticate_user, change_password, log_user_activity

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate_user(username, password):
            log_user_activity(username, 'login')
            return redirect(url_for('main.change_password'))
    return render_template('login.html')

@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        if change_password(username, new_password):
            log_user_activity(username, 'password_change')
            return "Password changed successfully"
    return render_template('change_password.html')