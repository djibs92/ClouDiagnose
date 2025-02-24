from flask import Blueprint, request, jsonify
from app.models.models import db, User
from flask_jwt_extended import create_access_token

user_bp = Blueprint("user", __name__)

@user_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email et mot de passe requis"}), 400

    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return jsonify({"error": "Email déjà utilisé"}), 400

    new_user = User(email=data["email"])
    new_user.set_password(data["password"])  # Hash du mot de passe
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Utilisateur créé !"}), 201

@user_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email et mot de passe requis"}), 400

    user = User.query.filter_by(email=data["email"]).first()
    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Identifiants incorrects"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": access_token}), 200



