import re
from ldap3 import Connection
from database import save_password
from auth import get_ldap_connection
import os

def is_password_secure(password):
    # ... (прежние проверки безопасности) ...

def change_password(username, new_password, old_password):
    if not is_password_secure(new_password):
        return False
    
    try:
        # Аутентификация пользователя для самосмены пароля
        user_dn = f"CN={username},CN=Users,DC={os.getenv('AD_DOMAIN').replace('.', ',DC=')}"
        
        with Connection(
            get_ldap_connection(),
            user=user_dn,
            password=old_password
        ) as conn:
            if not conn.bind():
                return False
            
            # Изменение пароля с использованием старого пароля
            result = conn.extend.microsoft.modify_password(
                user_dn, 
                new_password, 
                old_password
            )
            
            if result:
                save_password(username, new_password)
                return True
            return False
            
    except Exception as e:
        print(f"Password change error: {e}")
        return False