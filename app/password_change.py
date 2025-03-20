import re
import logging
from ldap3 import Connection
from ldap3.core.exceptions import LDAPException
from database import save_password
from auth import get_ldap_connection
import os

logger = logging.getLogger(__name__)

def is_password_secure(password):
    checks = {
        'length': len(password) >= 12,
        'lower': re.search(r'[a-z]', password) is not None,
        'upper': re.search(r'[A-Z]', password) is not None,
        'digit': re.search(r'\d', password) is not None,
        'special': re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
    }
    logger.debug(f"Проверка пароля: {checks}")
    return all(checks.values())

def change_password(username, new_password, old_password):
    try:
        if not is_password_secure(new_password):
            logger.error("Пароль не соответствует требованиям безопасности")
            return False, "Пароль не соответствует требованиям безопасности"

        domain_components = os.getenv('AD_DOMAIN').split('.')
        base_dn = ','.join([f"DC={component}" for component in domain_components])
        user_dn = f"CN={username},OU=zitadel,{base_dn}"
        logger.debug(f"Попытка смены пароля для: {user_dn}")

        with Connection(get_ldap_connection(), user=user_dn, password=old_password) as conn:
            if not conn.bind():
                logger.error("Ошибка привязки LDAP: Неверный старый пароль")
                return False, "Неверный текущий пароль"
            
            logger.info("Привязка LDAP успешна, изменение пароля...")
            result = conn.extend.microsoft.modify_password(
                user_dn, 
                new_password, 
                old_password
            )
            
            if result:
                logger.info("Пароль успешно изменен в AD")
                try:
                    save_password(username, new_password)
                    return True, "Пароль успешно изменен"
                except Exception as db_error:
                    logger.error(f"Ошибка сохранения в базе данных: {str(db_error)}")
                    return False, "Пароль изменен в AD, но не удалось сохранить в базе данных"
            
            logger.error(f"Ошибка изменения пароля LDAP: {conn.result}")
            return False, "Не удалось изменить пароль в Active Directory"

    except LDAPException as e:
        logger.error(f"Ошибка LDAP: {str(e)}")
        return False, "Ошибка связи с Active Directory"
        
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {str(e)}")
        return False, "Техническая ошибка при смене пароля"