from ldap3 import Server, Connection, ALL, Tls
import ssl
import os

def get_ldap_connection():
    tls_configuration = Tls(validate=ssl.CERT_REQUIRED) if os.getenv('USE_SSL') == 'True' else None
    server = Server(
        os.getenv('AD_SERVER'), 
        use_ssl=(os.getenv('USE_SSL') == 'True'),
        tls=tls_configuration
    )
    return server

def authenticate_user(username, password):
    try:
        server = get_ldap_connection()
        conn = Connection(
            server, 
            user=f'{username}@{os.getenv("AD_DOMAIN")}', 
            password=password
        )
        return conn.bind()
    except Exception as e:
        print(f"Ошибка аутентификации: {e}")
        return False