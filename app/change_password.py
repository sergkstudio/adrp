from flask import request, jsonify, render_template
from app import app
from ldap3 import Server, Connection, MODIFY_REPLACE
import os

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        domain = os.getenv('DOMAIN')
        admin_user = os.getenv('ADMIN_USER')
        admin_password = os.getenv('ADMIN_PASSWORD')

        server = Server(domain, get_info=ALL)
        conn = Connection(server, user=admin_user, password=admin_password, authentication='NTLM')

        if conn.bind():
            conn.modify(f'CN={username},DC=klepinin,DC=space', {'unicodePwd': [(MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])]})
            if conn.result['result'] == 0:
                with open('password_changes.log', 'a') as log_file:
                    log_file.write(f'User: {username}, New Password: {new_password}\n')
                return jsonify({'message': 'Password changed successfully'}), 200
            else:
                return jsonify({'message': 'Failed to change password'}), 400
        else:
            return jsonify({'message': 'Admin authentication failed'}), 401
    return render_template('change_password.html')
