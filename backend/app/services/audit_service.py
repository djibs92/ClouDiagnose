import boto3
from datetime import datetime,timedelta
import subprocess
import json
import os

from config import AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION

def get_aws_client(service):
    return boto3.client(
        service,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )

def get_ec2_instances():
    ec2 = get_aws_client("ec2")
    instances = ec2.describe_instances()
    return instances["Reservations"]

def get_s3_buckets():
    s3 = get_aws_client("s3")
    buckets = s3.list_buckets()
    return [bucket["Name"] for bucket in buckets["Buckets"]]

def get_rds_instances():
    rds = get_aws_client("rds")
    instances = rds.describe_db_instances()
    return [db["DBInstanceIdentifier"] for db in instances["DBInstances"]]

def get_iam_users():
    iam = get_aws_client("iam")
    users = iam.list_users()
    return [user["UserName"] for user in users["Users"]]

def json_serial(obj):
    """Convertit les objets non JSON-sérialisables en chaînes de caractères pour l'erreur """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convertit en format lisible JSON
    raise TypeError(f"Type {type(obj)} non sérialisable")


def run_prowler():
    """ Exécute Prowler pour un audit de sécurité AWS et récupère le résultat JSON """
    try:
        command = ["prowler", "aws", "--output-formats", "json-asff", "--output-filename", "output.json"]
        result = subprocess.run(command, capture_output=True, text=True)

        # Afficher console
        print("=== Prowler Output ===")
        print(result.stdout)
        print("=== Prowler Errors ===")
        print(result.stderr)

        
        if not os.path.exists("output.json.asff.json"):
            return {
                "error": "Prowler n'a pas généré de fichier ",
                "stderr": result.stderr,
                "stdout": result.stdout
            }

        with open("output.json.asff.json", "r") as file:
            prowler_results = json.load(file)

        return {
            "message": "Audit Prowler terminé",
            "prowler_results": prowler_results,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except subprocess.CalledProcessError as e:
        return {
            "error": "Erreur Prowler",
            "stderr": e.stderr,
            "stdout": e.stdout
        }

    except Exception as e:
        return {
            "error": f"Erreur inattendue : {str(e)}"
        }
    
#Intégration de Cost Explorer
# Affichage si cost > a 0 . 
def get_cost_data():
    """ Récupère les dépenses AWS des 30 derniers jours (filtre les services inutilisés) """
    client = boto3.client(
        "ce",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )

    # Calcul sur période de 30 jours
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=30)

    response = client.get_cost_and_usage(
        TimePeriod={
            "Start": start_date.strftime("%Y-%m-%d"),
            "End": end_date.strftime("%Y-%m-%d"),
        },
        Granularity="DAILY",
        Metrics=["BlendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}]
    )
    cost_data = []
    for result in response["ResultsByTime"]:
        for group in result["Groups"]:
            service_name = group["Keys"][0]
            cost_amount = float(group["Metrics"]["BlendedCost"]["Amount"])

            if cost_amount > 0:  # On ne garde que les services qui ont généré un coût
                cost_data.append({"date": result["TimePeriod"]["Start"], "service": service_name, "cost": cost_amount})

    return cost_data



#Ajout de AWS Security Hub . 

def get_security_hub_findings():
    """Récupère les findings de AWS Security Hub et extrait les informations clés"""
    client = boto3.client(
        "securityhub",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )

    try:
        response = client.get_findings()
        findings = response.get("Findings", [])

        formatted_findings = [
            {
                "Title": f["Title"],
                "Severity": f["Severity"]["Label"],
                "Description": f["Description"],
                "Resource": f["Resources"][0]["Id"] if f.get("Resources") else "N/A"
            }
            for f in findings
        ]

        return formatted_findings

    except Exception as e:
        return {"error": f"Impossible de récupérer les findings de Security Hub : {str(e)}"}



#Intégration de Cost Explorer


# def get_cost_data():
#     """ Récupère les dépenses AWS des 30 derniers jours """
#     client = boto3.client(
#         "ce",
#         aws_access_key_id=AWS_ACCESS_KEY,
#         aws_secret_access_key=AWS_SECRET_KEY,
#         region_name=AWS_REGION
#     )
#     # Période de 30 jours 
#     end_date = datetime.utcnow().date()
#     start_date = end_date - timedelta(days=30)

#     response = client.get_cost_and_usage(
#         TimePeriod={
#             "Start": start_date.strftime("%Y-%m-%d"),
#             "End": end_date.strftime("%Y-%m-%d"),
#         },
#         Granularity="DAILY",
#         Metrics=["BlendedCost"],
#         GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}]
#     )

#     #Résultat des extractions 
#     cost_data = []
#     for result in response["ResultsByTime"]:
#         for group in result["Groups"]:
#             service_name = group["Keys"][0]
#             cost_amount = group["Metrics"]["BlendedCost"]["Amount"]
#             cost_data.append({"date": result["TimePeriod"]["Start"], "service": service_name, "cost": float(cost_amount)})

#     return cost_data
