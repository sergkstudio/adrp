from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_envvar('APP_SETTINGS')

    with app.app_context():
        from . import routes

    return app