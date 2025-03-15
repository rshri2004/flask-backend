from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from models import db, Account, DB_NAME
import os
from pathlib import Path

login_manager = LoginManager()
def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "secret_key"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"

    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "login"

    with app.app_context():
        db.create_all()

    return app


app = create_app()

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))  # Loads the user from the database

# Import these here to avoid circular imports but make them available for seed_initial_data
from models import DietType, PhysicalActivityLevel, AlcoholConsumption, Conditions, InterstitialFluidElement

from routes import *
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0')