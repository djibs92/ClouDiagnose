from flask import Blueprint, jsonify, send_file, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.audit_service import get_ec2_instances, get_s3_buckets, get_rds_instances, get_iam_users, json_serial,run_prowler,get_cost_data,get_security_hub_findings
from app.models.models import db, Audit
import json
import os


audit_bp = Blueprint("audit", __name__)

@audit_bp.route("/audit/start", methods=["POST"])
@jwt_required()
def start_audit():
    current_user = get_jwt_identity()

    # Récupération des ressources AWS
    ec2_instances = get_ec2_instances() 
    s3_buckets = get_s3_buckets()
    rds_instances = get_rds_instances()
    iam_users = get_iam_users()
    # security_results = run_prowler()
    cost_explorer_data = get_cost_data()
    security_findings = get_security_hub_findings()
    #Cloudwatch a rajouter.

    audit_data = {
        "ec2_instances": ec2_instances,
        "s3_buckets": s3_buckets,
        "rds_instances": rds_instances,
        "iam_users": iam_users,
        "cost_explorer":cost_explorer_data,
        "security_hub_findings":security_findings
        # "security_scan": security_results
        #Cloudwatch a rajouter.

    }

    # Sauvegarde en base
    # new_audit = Audit(user_id=current_user, status="completed", results=json.dumps(audit_data))
    new_audit = Audit(user_id=current_user, status="completed", results=json.dumps(audit_data, default=json_serial))
    db.session.add(new_audit)
    db.session.commit()

    return jsonify({"message": "Audit terminé ainsi que Prowler", "audit_results": audit_data}), 200


#Audit route pour récuperer l'historique des audits

@audit_bp.route("/audit/history", methods=["GET"])
@jwt_required()
def audit_history():
    current_user = get_jwt_identity()
    audits = Audit.query.filter_by(user_id=current_user).order_by(Audit.created_at.desc()).all()

    audit_list = []
    for audit in audits:
        audit_data = {
            "id": audit.id,
            "created_at": audit.created_at.isoformat(),
            "status": audit.status,
            "results_summary": audit.results  
        }
        audit_list.append(audit_data)

    return jsonify({"audits": audit_list}), 200


#Route de cost-Explorer 

@audit_bp.route("/audit/costs", methods=["GET"])
@jwt_required()
def get_aws_costs():
    current_user = get_jwt_identity()
    cost_data = get_cost_data()

    return jsonify({"message": "Analyse des coûts AWS", "cost_data": cost_data}), 200


#Route pour téléchargement audit au format JSON 

@audit_bp.route("/audit/download/<int:audit_id>", methods=["GET"])
@jwt_required()
def download_audit(audit_id):
    current_user = get_jwt_identity()

    # Vérifier si l'audit appartient à l'utilisateur
    audit = Audit.query.filter_by(id=audit_id, user_id=current_user).first()
    if not audit:
        return jsonify({"error": "Audit introuvable ou accès non autorisé"}), 403

    # Générer le contenu JSON en mémoire
    audit_json = json.dumps(json.loads(audit.results), indent=4)

    # Retourner le fichier JSON en réponse HTTP
    return Response(
        audit_json,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit_{audit_id}.json"}
    )


#