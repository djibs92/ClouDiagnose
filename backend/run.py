from flask import Flask
from config import SQLALCHEMY_DATABASE_URI
from app.models.models import db, init_db
from flask_jwt_extended import JWTManager
from app.routes.user import user_bp  
from app.routes.audit import audit_bp  


# Ajout du blueprint audit

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "supersecretkey"

jwt = JWTManager(app)

# Initialiser la base de données
db.init_app(app)


with app.app_context():
    # db.drop_all()  #recréer les tables juste pour le bug bdd
    db.create_all()  # Crée les nouvelles tables

# Enregistrer les routes
app.register_blueprint(user_bp, url_prefix="/user")
app.register_blueprint(audit_bp, url_prefix="/")
# app.register_blueprint(audit_bp, url_prefix="/audit/start")


# @app.route('/healthcheck') test
# def healthcheck():
#     return {"status": "OK"}, 200

if __name__ == '__main__':
    app.run(debug=True)


    