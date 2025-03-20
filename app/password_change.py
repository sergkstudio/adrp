import re
import logging
from ldap3 import Connection, LDAPException
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
    logger.debug(f"Password checks: {checks}")
    return all(checks.values())

def change_password(username, new_password, old_password):
    try:
        if not is_password_secure(new_password):
            logger.error("Password does not meet security requirements")
            return False, "Password does not meet security requirements"

        domain_components = os.getenv('AD_DOMAIN').split('.')
        base_dn = ','.join([f"DC={component}" for component in domain_components])
        user_dn = f"CN={username},CN=Users,{base_dn}"
        logger.debug(f"Attempting password change for: {user_dn}")

        with Connection(get_ldap_connection(), user=user_dn, password=old_password) as conn:
            if not conn.bind():
                logger.error("LDAP bind failed: Invalid old password")
                return False, "Invalid current password"
            
            logger.info("LDAP bind successful, modifying password...")
            result = conn.extend.microsoft.modify_password(
                user_dn, 
                new_password, 
                old_password
            )
            
            if result:
                logger.info("Password changed successfully in AD")
                try:
                    save_password(username, new_password)
                    return True, "Password changed successfully"
                except Exception as db_error:
                    logger.error(f"Database save failed: {str(db_error)}")
                    return False, "Password changed in AD but failed to save in database"
            
            logger.error(f"LDAP modify password failed: {conn.result}")
            return False, "Failed to change password in Active Directory"

    except LDAPException as e:
        logger.error(f"LDAP error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
        return False, "Technical error during password change"