from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models.models import db, User
from werkzeug.security import generate_password_hash, check_password_hash

user_bp = Blueprint("user", __name__)

###  Route d'inscription
@user_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email et mot de passe requis"}), 400

    # Vérifier si l'utilisateur existe déjà
    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return jsonify({"error": "Email déjà utilisé"}), 400

    # Hachage du mot de passe
    hashed_password = generate_password_hash(data["password"])
    
    # Création de l'utilisateur
    new_user = User(email=data["email"], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Utilisateur créé avec succès !"}), 201

### Route de connexion
@user_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email et mot de passe requis"}), 400

    # Vérifier l'utilisateur
    user = User.query.filter_by(email=data["email"]).first()
    if not user or not check_password_hash(user.password_hash, data["password"]):
        return jsonify({"error": "Identifiants incorrects"}), 401

    # Génération du token JWT
    access_token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": access_token}), 200

###  Route pour récupérer les infos de l'utilisateur connecté
@user_bp.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    return jsonify({
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat()
    }), 200

###  Route pour modifier le mot de passe
@user_bp.route("/update-password", methods=["POST"])
@jwt_required()
def update_password():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    if not data.get("old_password") or not data.get("new_password"):
        return jsonify({"error": "Ancien et nouveau mot de passe requis"}), 400

    user = User.query.get(current_user_id)
    if not user or not check_password_hash(user.password_hash, data["old_password"]):
        return jsonify({"error": "Ancien mot de passe incorrect"}), 401

    # Mise à jour du mot de passe
    user.password_hash = generate_password_hash(data["new_password"])
    db.session.commit()

    return jsonify({"message": "Mot de passe mis à jour avec succès"}), 200

###  Route pour supprimer un compte utilisateur
@user_bp.route("/delete-account", methods=["DELETE"])
@jwt_required()
def delete_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "Compte supprimé avec succès"}), 200