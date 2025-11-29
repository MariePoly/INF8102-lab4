import boto3
from botocore.exceptions import ClientError

# PARAMÈTRES
REGION = "ca-central-1"

ENVIRONMENT_NAME = "polystudent"

KEY_NAME = "polystudent-key"           
SECURITY_GROUP_NAME = "polystudent-sg" 
INSTANCE_PROFILE_NAME = "LabInstanceProfile"  

AMI_ID = "ami-0dd67d541aa70c8b9"       
INSTANCE_TYPE = "t3.micro"

VOLUME_SIZE_GB = 20                  

# Tags Name des subnets créés par  VPC
PUBLIC_SUBNET_AZ1_TAG  = "polystudent-public-az1"
PUBLIC_SUBNET_AZ2_TAG  = "polystudent-public-az2"
PRIVATE_SUBNET_AZ1_TAG = "polystudent-private-az1"
PRIVATE_SUBNET_AZ2_TAG = "polystudent-private-az2"

# Seuil pour l’alarme CloudWatch : 1000 paquets/s
PKTS_THRESHOLD = 1000

ec2_client = boto3.client("ec2", region_name=REGION)
ec2 = boto3.resource("ec2", region_name=REGION)
cloudwatch = boto3.client("cloudwatch", region_name=REGION)
iam = boto3.client("iam", region_name=REGION)


#Fonctions 

def get_subnet_id_by_tag(name_tag):
    """Retourne (subnet_id, vpc_id) pour un subnet avec tag Name=name_tag."""
    resp = ec2_client.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": [name_tag]}]
    )
    if not resp["Subnets"]:
        raise RuntimeError(f"Subnet avec tag Name='{name_tag}' introuvable")
    subnet = resp["Subnets"][0]
    return subnet["SubnetId"], subnet["VpcId"]


def get_security_group_id(group_name, vpc_id):
    """Retourne l’ID du SG dans le VPC donné."""
    resp = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [group_name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    if not resp["SecurityGroups"]:
        raise RuntimeError(f"Security group '{group_name}' introuvable dans le VPC {vpc_id}")
    return resp["SecurityGroups"][0]["GroupId"]


def get_instance_profile_arn(profile_name):
    """Retourne l’ARN de l’instance profile (LabInstanceProfile)."""
    resp = iam.get_instance_profile(InstanceProfileName=profile_name)
    return resp["InstanceProfile"]["Arn"]


def create_ec2_instance(subnet_id, sg_id, instance_profile_arn, name_tag):
    """Crée UNE instance EC2 dans un subnet donné et retourne l’objet instance."""
    print(f"Création de l’instance EC2 '{name_tag}' dans {subnet_id}...")

    instances = ec2.create_instances(
        ImageId=AMI_ID,
        InstanceType=INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        KeyName=KEY_NAME,
        NetworkInterfaces=[
            {
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": [sg_id],
                "AssociatePublicIpAddress": True,  # pas de route vers IGW
            }
        ],
        IamInstanceProfile={"Arn": instance_profile_arn},
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "DeleteOnTermination": True,
                    "VolumeSize": VOLUME_SIZE_GB,
                    "VolumeType": "gp3",
                },
            }
        ],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": name_tag},
                    {"Key": "Environment", "Value": ENVIRONMENT_NAME},
                ],
            }
        ],
    )

    instance = instances[0]
    print("  Instance créée, ID :", instance.id)
    print("  Attente de l’état 'running'...")
    instance.wait_until_running()
    instance.reload()
    print("  Instance en cours d’exécution. IP publique :", instance.public_ip_address)
    return instance


def create_network_packets_alarm(instance_id, instance_name):
    """
    Crée une alarme CloudWatch sur NetworkPacketsIn (pkts/s),
    seuil moyen PKTS_THRESHOLD.
    """
    alarm_name = f"{ENVIRONMENT_NAME}-{instance_name}-NetworkPacketsIn"

    print(f"  Création de l’alarme CloudWatch '{alarm_name}' pour {instance_id}...")

    cloudwatch.put_metric_alarm(
        AlarmName=alarm_name,
        AlarmDescription=(
            f"Surveille le nombre de paquets entrants sur {instance_name} "
            f"(seuil {PKTS_THRESHOLD} pkts/s)."
        ),
        Namespace="AWS/EC2",
        MetricName="NetworkPacketsIn",
        Dimensions=[
            {"Name": "InstanceId", "Value": instance_id}
        ],
        Statistic="Average",
        Period=60,                 
        EvaluationPeriods=1,
        Threshold=PKTS_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        ActionsEnabled=False       # pas d’action auto (sns, etc.) 
    )

    print(f"  Alarme '{alarm_name}' créée.")


# ---------- main ----------

def main():
    try:
        # 1) Récupérer les subnets (et le VPC)
        print("Recherche des subnets publics/privés...")
        pub1_subnet_id, vpc_id = get_subnet_id_by_tag(PUBLIC_SUBNET_AZ1_TAG)
        pub2_subnet_id, _      = get_subnet_id_by_tag(PUBLIC_SUBNET_AZ2_TAG)
        priv1_subnet_id, _     = get_subnet_id_by_tag(PRIVATE_SUBNET_AZ1_TAG)
        priv2_subnet_id, _     = get_subnet_id_by_tag(PRIVATE_SUBNET_AZ2_TAG)

        print("  VPC ID      :", vpc_id)
        print("  Public AZ1  :", pub1_subnet_id)
        print("  Public AZ2  :", pub2_subnet_id)
        print("  Private AZ1 :", priv1_subnet_id)
        print("  Private AZ2 :", priv2_subnet_id)

        # 2) Security group et Instance Profile
        print("\nRecherche du security group...")
        sg_id = get_security_group_id(SECURITY_GROUP_NAME, vpc_id)
        print("  SG ID :", sg_id)

        print("\nRecherche de l’instance profile IAM...")
        instance_profile_arn = get_instance_profile_arn(INSTANCE_PROFILE_NAME)
        print("  Instance profile ARN :", instance_profile_arn)

        # 3) Création des 4 instances
        print("\n=== Création des instances EC2 ===")
        inst_pub1 = create_ec2_instance(pub1_subnet_id, sg_id, instance_profile_arn,
                                        "polystudent-ec2-public-az1")
        inst_pub2 = create_ec2_instance(pub2_subnet_id, sg_id, instance_profile_arn,
                                        "polystudent-ec2-public-az2")
        inst_priv1 = create_ec2_instance(priv1_subnet_id, sg_id, instance_profile_arn,
                                         "polystudent-ec2-private-az1")
        inst_priv2 = create_ec2_instance(priv2_subnet_id, sg_id, instance_profile_arn,
                                         "polystudent-ec2-private-az2")

        # 4) Création des alarmes CloudWatch pour chaque instance
        print("\n=== Création des alarmes CloudWatch (NetworkPacketsIn) ===")
        create_network_packets_alarm(inst_pub1.id,  "ec2-public-az1")
        create_network_packets_alarm(inst_pub2.id,  "ec2-public-az2")
        create_network_packets_alarm(inst_priv1.id, "ec2-private-az1")
        create_network_packets_alarm(inst_priv2.id, "ec2-private-az2")

        print("\nToutes les instances et alarmes ont été créées avec succès.")

    except ClientError as e:
        print("Erreur AWS :", e)
    except RuntimeError as e:
        print("Erreur de configuration :", e)


if __name__ == "__main__":
    main()
