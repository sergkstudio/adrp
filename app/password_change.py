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

def admin_change_password(target_username, new_password):
    try:
        if not is_password_secure(new_password):
            logger.error("Пароль не соответствует требованиям безопасности")
            return False, "Пароль не соответствует требованиям безопасности"

        # Получаем данные администратора из переменных окружения
        admin_username = os.getenv('AD_ADMIN_USER')
        admin_password = os.getenv('AD_ADMIN_PASSWORD')
        
        domain_components = os.getenv('AD_DOMAIN').split('.')
        base_dn = ','.join([f"DC={component}" for component in domain_components])
        
        # Формируем DN целевого пользователя и администратора
        target_user_dn = f"CN={target_username},CN=Users,{base_dn}"
        admin_user_dn = f"CN={admin_username},CN=Users,{base_dn}"
        
        logger.debug(f"Попытка смены пароля для: {target_user_dn}")
        logger.debug(f"Используется администратор: {admin_user_dn}")

        # Подключаемся как администратор
        with Connection(
            get_ldap_connection(),
            user=admin_user_dn,
            password=admin_password,
            authentication="SIMPLE"
        ) as conn:
            if not conn.bind():
                logger.error("Ошибка аутентификации администратора")
                return False, "Ошибка аутентификации администратора"
            
            logger.info("Успешная аутентификация администратора")
            
            # Изменяем пароль без старого пароля
            result = conn.extend.microsoft.modify_password(
                target_user_dn, 
                new_password
            )
            
            if result:
                logger.info("Пароль успешно изменен в AD")
                try:
                    # Сохраняем в базу данных при необходимости
                    save_password(target_username, new_password)
                    return True, "Пароль успешно изменен"
                except Exception as db_error:
                    logger.error(f"Ошибка сохранения в базе данных: {str(db_error)}")
                    return False, "Пароль изменен в AD, но не удалось сохранить в БД"
            
            logger.error(f"Ошибка изменения пароля: {conn.result}")
            return False, "Не удалось изменить пароль в Active Directory"

    except LDAPException as e:
        error_message = f"Ошибка LDAP: {str(e)}"
        if 'insufficientAccessRights' in str(e):
            error_message += " | Недостаточно прав администратора"
        logger.error(error_message)
        return False, error_message
        
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {str(e)}")
        return False, "Техническая ошибка при смене пароля"