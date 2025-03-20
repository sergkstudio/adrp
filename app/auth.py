from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import os

def authenticate_user(username, password):
    # Логика аутентификации пользователя
    return True

def change_password(username, new_password):
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')
    ldap_server = os.getenv('LDAP_SERVER')
    base_dn = os.getenv('BASE_DN')

    # Создаем сервер и соединение
    server = Server(ldap_server, get_info=ALL)
    conn = Connection(server, user=admin_user, password=admin_password, auto_bind=True)

    # Формируем DN пользователя
    user_dn = f"cn={username},ou=users,{base_dn}"

    # Изменяем пароль
    conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [new_password])]})

    # Закрываем соединение
    conn.unbind()
    return True

def log_user_activity(username, action):
    with open('user_activity.log', 'a') as log_file:
        log_file.write(f"{username} performed {action}\n")