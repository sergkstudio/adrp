from flask import Flask, render_template, request, redirect, url_for, flash
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, validators
import os
from dotenv import load_dotenv

# Загружаем переменные окружения из .env
load_dotenv()

# Инициализация Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///passwords.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')

# Инициализация SQLAlchemy
db = SQLAlchemy(app)

# Модель для хранения паролей в базе данных
class UserPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Настройки для подключения к AD
AD_SERVER = os.getenv('AD_SERVER', 'your_ad_server')  # Адрес сервера AD
AD_DOMAIN = os.getenv('AD_DOMAIN', 'your_domain')    # Домен
AD_USER = os.getenv('AD_USER', 'admin_user')         # Учетная запись с правами на изменение паролей
AD_PASSWORD = os.getenv('AD_PASSWORD', 'admin_password')  # Пароль для учетной записи

# Форма для авторизации
class LoginForm(Form):
    username = StringField('Username', [validators.InputRequired()])
    password = PasswordField('Password', [validators.InputRequired()])

# Форма для изменения пароля
class ChangePasswordForm(Form):
    new_password = PasswordField('New Password', [
        validators.InputRequired(),
        validators.Length(min=12),
        validators.Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)',
                          message="Password must contain at least one digit, one lowercase letter, one uppercase letter, and one special character.")
    ])

# Маршрут для авторизации
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        # Подключение к AD для проверки учетных данных
        server = Server(AD_SERVER, get_info=ALL)
        conn = Connection(server, user=f'{username}@{AD_DOMAIN}', password=password, authentication=NTLM)

        if conn.bind():
            return redirect(url_for('change_password', username=username))
        else:
            flash('Invalid credentials')

    return render_template('login.html', form=form)

# Маршрут для изменения пароля
@app.route('/change_password/<username>', methods=['GET', 'POST'])
def change_password(username):
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        new_password = form.new_password.data

        # Подключение к AD с правами администратора для изменения пароля
        server = Server(AD_SERVER, get_info=ALL)
        admin_conn = Connection(server, user=f'{AD_USER}@{AD_DOMAIN}', password=AD_PASSWORD, authentication=NTLM)

        if admin_conn.bind():
            # Поиск пользователя в AD
            search_filter = f'(sAMAccountName={username})'
            admin_conn.search('dc=your_domain,dc=com', search_filter, attributes=['distinguishedName'])

            if admin_conn.entries:
                user_dn = admin_conn.entries[0].distinguishedName.value

                # Изменение пароля в AD
                admin_conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])})

                if admin_conn.result['result'] == 0:
                    # Сохранение нового пароля в базу данных
                    user_password = UserPassword(username=username, password=new_password)
                    db.session.add(user_password)
                    db.session.commit()

                    flash('Password changed successfully')
                else:
                    flash('Failed to change password in AD')
            else:
                flash('User not found in AD')
        else:
            flash('Failed to connect to AD as admin')

        return redirect(url_for('login'))

    return render_template('change_password.html', form=form)

# Инициализация базы данных
with app.app_context():
    db.create_all()

# Запуск приложения
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)