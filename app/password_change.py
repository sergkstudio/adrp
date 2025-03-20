import re
from ldap3 import Connection
from database import save_password
from auth import get_ldap_connection
import os

def is_password_secure(password):
    if len(password) < 12:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def change_password(username, new_password, old_password):
    if not is_password_secure(new_password):
        return False
    
    try:
        # Аутентификация пользователя для самосмены пароля
        domain_components = os.getenv('AD_DOMAIN').split('.')
        base_dn = ','.join([f"DC={component}" for component in domain_components])
        user_dn = f"CN={username},CN=Users,{base_dn}"
        
        with Connection(
            get_ldap_connection(),
            user=user_dn,
            password=old_password
        ) as conn:
            if not conn.bind():
                return False
            
            # Изменение пароля
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