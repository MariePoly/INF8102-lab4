import boto3
from botocore.exceptions import ClientError

INBOUND_PORTS = [
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    3389,  # RDP
    1433,  # MS SQL
    5432,  # PostgreSQL
    3306,  # MySQL
    27017  # MongoDB
]

KEY_NAME = "polystudent-key"  
SECURITY_GROUP_NAME = "polystudent-sg"  
PUBLIC_SUBNET_TAG = "polystudent-public-az1"  
IAM_INSTANCE_PROFILE_NAME = "LabInstanceProfile" 
AMI_ID = "ami-0dd67d541aa70c8b9"  
INSTANCE_TYPE = "t3.micro"
VOLUME_SIZE_GB = 80

ec2 = boto3.resource("ec2")
ec2_client = boto3.client("ec2")
iam_client = boto3.client("iam")


def get_security_group_id(group_name, vpc_id):
    resp = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [group_name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    if resp["SecurityGroups"]:
        return resp["SecurityGroups"][0]["GroupId"]

    print(f"  Aucun security group '{group_name}' dans le VPC {vpc_id}, création...")

    sg = ec2.create_security_group(
        GroupName=group_name,
        Description="polystudent security group for web/db access",
        VpcId=vpc_id,
    )

    sg.create_tags(Tags=[
        {"Key": "Name", "Value": "polystudent-sg1"},
        {"Key": "Environment", "Value": "polystudent"},
    ])

    # INBOUND_PORTS
    ip_permissions = []
    for port in INBOUND_PORTS:
        ip_permissions.append({
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })
    sg.authorize_ingress(IpPermissions=ip_permissions)

    print("  Security group créé dans le bon VPC :", sg.id)
    return sg.id


def get_public_subnet_id_by_tag(name_tag):
    resp = ec2_client.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": [name_tag]}]
    )
    if not resp["Subnets"]:
        raise RuntimeError(f"Subnet avec tag Name='{name_tag}' introuvable")
    subnet = resp["Subnets"][0]
    return subnet["SubnetId"], subnet["VpcId"]


def get_instance_profile_arn(profile_name):
    resp = iam_client.get_instance_profile(InstanceProfileName=profile_name)
    return resp["InstanceProfile"]["Arn"]


def create_secure_ec2_instance():
    try:
        print("Recherche du subnet public AZ1...")
        subnet_id, vpc_id = get_public_subnet_id_by_tag(PUBLIC_SUBNET_TAG)
        print("  Subnet ID :", subnet_id)
        print("  VPC ID    :", vpc_id)

        print("Recherche du security group...")
        sg_id = get_security_group_id(SECURITY_GROUP_NAME, vpc_id)
        print("  SG ID :", sg_id)

        print("Recherche de l'instance profile IAM...")
        instance_profile_arn = get_instance_profile_arn(IAM_INSTANCE_PROFILE_NAME)
        print("  Instance profile ARN :", instance_profile_arn)

        print("Création de l’instance EC2...")

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
                    "AssociatePublicIpAddress": True,
                }
            ],
            IamInstanceProfile={"Arn": instance_profile_arn},
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "DeleteOnTermination": False,
                        "VolumeSize": VOLUME_SIZE_GB,
                        "VolumeType": "gp3",
                    },
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": "polystudent-ec2"},
                        {"Key": "Environment", "Value": "polystudent"},
                    ],
                }
            ],
        )

        instance = instances[0]
        print("Instance créée, ID :", instance.id)
        print("Attente de l’état 'running'...")
        instance.wait_until_running()
        instance.reload()
        print("Instance en cours d’exécution, IP publique :", instance.public_ip_address)

    except ClientError as e:
        print("Erreur AWS :", e)
    except RuntimeError as e:
        print("Erreur de configuration :", e)


if __name__ == "__main__":
    create_secure_ec2_instance()