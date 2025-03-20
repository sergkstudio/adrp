import ldap
import os

def authenticate_user(username, password):
    # Логика аутентификации пользователя
    return True

def change_password(username, new_password):
    admin_user = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')
    ldap_server = os.getenv('LDAP_SERVER')
    base_dn = os.getenv('BASE_DN')

    conn = ldap.initialize(f'ldap://{ldap_server}')
    conn.simple_bind_s(admin_user, admin_password)

    dn = f"cn={username},ou=users,{base_dn}"
    password_mod = [(ldap.MOD_REPLACE, 'userPassword', new_password.encode())]
    conn.modify_s(dn, password_mod)
    conn.unbind_s()
    return True

def log_user_activity(username, action):
    with open('user_activity.log', 'a') as log_file:
        log_file.write(f"{username} performed {action}\n")