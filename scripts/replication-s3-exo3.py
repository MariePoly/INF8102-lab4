import json
import boto3
from botocore.exceptions import ClientError

# ========= PARAMÈTRES =========
REGION = "ca-central-1"

SOURCE_BUCKET = "polystudents3-tp4-marie"            # bucket de la question 2
DEST_BUCKET = "polystudents3-back-tp4-marie"         # bucket de réplication
TRAIL_BUCKET = "polystudents3-cloudtrail-tp4-marie"  # bucket qui reçoit les logs CloudTrail
TRAIL_NAME = "polystudent-s3-trail"

KMS_KEY_ALIAS = "alias/polystudent-kms1"

s3 = boto3.client("s3", region_name=REGION)
kms = boto3.client("kms", region_name=REGION)
iam = boto3.client("iam")
sts = boto3.client("sts")
cloudtrail = boto3.client("cloudtrail", region_name=REGION)

ACCOUNT_ID = sts.get_caller_identity()["Account"]


# ---------- Utilitaires ----------

def get_kms_key_arn(alias_name: str) -> str:
    """Retourne l'ARN de la clé KMS (alias/polystudent-kms1)."""
    if not alias_name.startswith("alias/"):
        alias_name = f"alias/{alias_name}"

    resp = kms.describe_key(KeyId=alias_name)
    return resp["KeyMetadata"]["Arn"]


def ensure_bucket(bucket_name: str, kms_arn: str | None = None):
    """
    Crée le bucket s'il n'existe pas, avec ACL privée, blocage d'accès public,
    chiffrement KMS (optionnel) et versioning activé.
    """
    try:
        s3.head_bucket(Bucket=bucket_name)
        print(f"Bucket '{bucket_name}' existe déjà → OK")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("404", "NoSuchBucket"):
            print(f"Création du bucket S3 '{bucket_name}' en {REGION} (ACL=private)...")
            s3.create_bucket(
                Bucket=bucket_name,
                ACL="private",
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        else:
            raise

    # Blocage accès public
    print(f"  Configuration du blocage de l’accès public pour {bucket_name}...")
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Chiffrement côté serveur (optionnel pour TRAIL_BUCKET)
    if kms_arn is not None:
        print(f"  Chiffrement SSE-KMS activé pour {bucket_name} avec {kms_arn}...")
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_arn,
                        }
                    }
                ]
            },
        )

    # Versioning
    print(f"  Activation du versioning sur {bucket_name}...")
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )


def ensure_cloudtrail_bucket_policy(bucket_name: str, account_id: str):
    """
    Configure la bucket policy minimale requise pour que CloudTrail
    puisse écrire ses logs dans le bucket S3 spécifié.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    }

    print(f"  Configuration de la bucket policy CloudTrail sur {bucket_name}...")
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(policy),
    )


# ---------- IAM pour la réplication S3 ----------

def ensure_replication_role(account_id: str) -> str:
    """
    Crée (si besoin) le rôle IAM que S3 utilisera pour répliquer les objets.
    Retourne l'ARN du rôle.
    """
    role_name = "polystudent-s3-replication-role"
    try:
        resp = iam.get_role(RoleName=role_name)
        print("Rôle IAM de réplication déjà présent → OK")
        return resp["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

    print("Création du rôle IAM de réplication S3...")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = resp["Role"]["Arn"]

    # Politique inline minimale pour la réplication S3 (source + destination)
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetReplicationConfiguration",
                    "s3:ListBucket"
                ],
                "Resource": [f"arn:aws:s3:::{SOURCE_BUCKET}"]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersion",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging"
                ],
                "Resource": [f"arn:aws:s3:::{SOURCE_BUCKET}/*"]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                    "s3:ReplicateTags",
                    "s3:GetObjectVersionTagging",
                    "s3:PutBucketVersioning",
                    "s3:PutObjectAcl"
                ],
                "Resource": [
                    f"arn:aws:s3:::{DEST_BUCKET}",
                    f"arn:aws:s3:::{DEST_BUCKET}/*"
                ]
            }
        ]
    }

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="polystudent-s3-replication-policy",
        PolicyDocument=json.dumps(policy_document),
    )

    print("Rôle IAM de réplication créé :", role_arn)
    return role_arn


def enable_replication(role_arn: str):
    """
    Active la réplication du bucket SOURCE_BUCKET vers DEST_BUCKET.
    """
    dest_arn = f"arn:aws:s3:::{DEST_BUCKET}"

    print("Configuration de la réplication S3 (source -> destination)...")
    s3.put_bucket_replication(
        Bucket=SOURCE_BUCKET,
        ReplicationConfiguration={
            "Role": role_arn,
            "Rules": [
                {
                    "ID": "polystudent-replication-rule",
                    "Priority": 1,
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {
                        "Bucket": dest_arn,
                        "StorageClass": "STANDARD",
                    },
                }
            ],
        },
    )
    print("Réplication activée entre", SOURCE_BUCKET, "et", DEST_BUCKET)


# ---------- CloudTrail pour les objets S3 ----------

def enable_cloudtrail_for_bucket():
    """
    Crée un trail CloudTrail qui journalise les data events S3
    (création / modification / suppression d'objets) sur SOURCE_BUCKET.
    """
    # 1) S’assurer que le bucket de logs CloudTrail existe
    ensure_bucket(TRAIL_BUCKET, kms_arn=None)

    # 2) Ajouter la bucket policy nécessaire pour CloudTrail
    ensure_cloudtrail_bucket_policy(TRAIL_BUCKET, ACCOUNT_ID)

    # 3) Vérifier si le trail existe déjà
    resp = cloudtrail.describe_trails(
        trailNameList=[TRAIL_NAME],
        includeShadowTrails=False
    )
    trail_list = resp.get("trailList", [])
    if not trail_list:
        print("Création du trail CloudTrail...")
        cloudtrail.create_trail(
            Name=TRAIL_NAME,
            S3BucketName=TRAIL_BUCKET,
            IsMultiRegionTrail=True,
        )
    else:
        print("Trail CloudTrail existe déjà → OK")

    # 4) Activer le trail
    print("Activation du trail CloudTrail...")
    cloudtrail.start_logging(Name=TRAIL_NAME)

    # 5) Configurer les data events sur le bucket SOURCE_BUCKET
    bucket_arn = f"arn:aws:s3:::{SOURCE_BUCKET}/"

    print("Configuration des data events CloudTrail sur le bucket", SOURCE_BUCKET)
    cloudtrail.put_event_selectors(
        TrailName=TRAIL_NAME,
        AdvancedEventSelectors=[
            {
                "Name": "S3DataEvents",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                    {"Field": "resources.ARN", "StartsWith": [bucket_arn]},
                ],
            }
        ],
    )


# ---------- Main ----------

def main():
    try:
        print("Compte AWS :", ACCOUNT_ID)

        kms_arn = get_kms_key_arn(KMS_KEY_ALIAS)
        print("KMS ARN :", kms_arn)

        # 1) Buckets + sécurité
        ensure_bucket(SOURCE_BUCKET, kms_arn=kms_arn)
        ensure_bucket(DEST_BUCKET, kms_arn=kms_arn)

        # 2) Rôle IAM + réplication
        role_arn = ensure_replication_role(ACCOUNT_ID)
        enable_replication(role_arn)

        # 3) CloudTrail pour les objets du bucket source
        enable_cloudtrail_for_bucket()

        print("\n== Configuration S3 / Réplication / CloudTrail terminée avec succès ==")

    except ClientError as e:
        print("Erreur AWS :", e)


if __name__ == "__main__":
    main()
