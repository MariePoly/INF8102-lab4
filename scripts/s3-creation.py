import boto3
from botocore.exceptions import ClientError


REGION = "ca-central-1"                 
BUCKET_NAME = "polystudents3-tp4-marie"     
KMS_KEY_ALIAS = "alias/polystudent-kms1" 

s3 = boto3.client("s3", region_name=REGION)
kms = boto3.client("kms", region_name=REGION)


def get_kms_key_arn(alias_name: str) -> str:
    """Retourne l'ARN de la clé KMS (alias/polystudent-kms1)."""
    if not alias_name.startswith("alias/"):
        alias_name = f"alias/{alias_name}"

    resp = kms.describe_key(KeyId=alias_name)
    return resp["KeyMetadata"]["Arn"]


def create_secure_bucket():
    try:
        print("Récupération de l'ARN de la clé KMS...")
        kms_arn = get_kms_key_arn(KMS_KEY_ALIAS)
        print("  KMS ARN :", kms_arn)

        print(f"Création du bucket S3 '{BUCKET_NAME}' en {REGION} (ACL=private)...")
        # Création du bucket
        s3.create_bucket(
            Bucket=BUCKET_NAME,
            ACL="private",
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )

        # Bloqyue accès public 
        print("Configuration blocage accès public...")
        s3.put_public_access_block(
            Bucket=BUCKET_NAME,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Chiffrement côté serveur avec KMS (comme dans Fig. 11)
        print("Configuration du chiffrement côté serveur (SSE-KMS)...")
        s3.put_bucket_encryption(
            Bucket=BUCKET_NAME,
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

        # Versioning activé (Status=Enabled)
        print("Activation du versioning du bucket...")
        s3.put_bucket_versioning(
            Bucket=BUCKET_NAME,
            VersioningConfiguration={"Status": "Enabled"},
        )

        print(f"Bucket sécurisé créé : {BUCKET_NAME}")
        print("   - ACL privée")
        print("   - Accès public bloqué")
        print("   - Chiffrement KMS avec", kms_arn)
        print("   - Versioning activé")

    except ClientError as e:
        print("Erreur AWS :", e)


if __name__ == "__main__":
    create_secure_bucket()