from flask import request, jsonify, render_template
from app import app
from ldap3 import Server, Connection, ALL
import os

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        domain = os.getenv('DOMAIN')

        server = Server(domain, get_info=ALL)
        conn = Connection(server, user=f'{domain}\\{username}', password=password, authentication='NTLM')

        if conn.bind():
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    return render_template('login.html')
