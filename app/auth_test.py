import os
from ldap3 import Server, Connection, Tls
import ssl
from dotenv import load_dotenv

load_dotenv()

def test_ad_connection():
    tls_config = Tls(validate=ssl.CERT_REQUIRED) if os.getenv('USE_SSL') == 'True' else None
    server = Server(
        os.getenv('AD_SERVER'),
        use_ssl=(os.getenv('USE_SSL') == 'True'),
        tls=tls_config
    )
    
    try:
        conn = Connection(
            server,
            user=f"{os.getenv('AD_ADMIN_USER')}@{os.getenv('AD_DOMAIN')}",
            password=os.getenv('AD_ADMIN_PASSWORD')
        )
        
        if conn.bind():
            print("✅ Успешное подключение к AD!")
            print("Результат:", conn.result)
            return True
        else:
            print("❌ Ошибка подключения:", conn.result)
            return False
            
    except Exception as e:
        print("🔥 Критическая ошибка:", str(e))
        return False

if __name__ == '__main__':
    test_ad_connection()