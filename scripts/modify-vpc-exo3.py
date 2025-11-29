import boto3
from botocore.exceptions import ClientError

# PARAMÈTRES 
ENVIRONMENT_NAME = "polystudent"        # Ajout d'un tag vpc1
VPC_CIDR = "10.0.0.0/16"
PUBLIC_SUBNET1_CIDR = "10.0.0.0/24"     # Public subnet AZ1
PUBLIC_SUBNET2_CIDR = "10.0.16.0/24"    # Public subnet AZ2
PRIVATE_SUBNET1_CIDR = "10.0.128.0/24"  # Private subnet AZ1
PRIVATE_SUBNET2_CIDR = "10.0.144.0/24"  # Private subnet AZ2

AZ1 = "ca-central-1a"
AZ2 = "ca-central-1b"

# Bucket S3 qui reçoit les Flow Logs 
S3_FLOW_LOG_BUCKET = "polystudents3-tp4-marie" 
S3_FLOW_LOG_ARN = f"arn:aws:s3:::{S3_FLOW_LOG_BUCKET}"

# SECURITY GROUPS (Ports) - Figure 9
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

ec2 = boto3.resource("ec2")
ec2_client = boto3.client("ec2")


def tag(resource, name):
    resource.create_tags(Tags=[
        {"Key": "Name", "Value": f"{ENVIRONMENT_NAME}-{name}"},
        {"Key": "Environment", "Value": ENVIRONMENT_NAME},
    ])

# VPC - Figure 1
def create_vpc():
    print("Création du VPC")
    vpc = ec2.create_vpc(CidrBlock=VPC_CIDR)
    vpc.wait_until_available()

    vpc.modify_attribute(EnableDnsSupport={"Value": True})
    vpc.modify_attribute(EnableDnsHostnames={"Value": True})

    tag(vpc, "vpc1")
    print(f"VPC créé : {vpc.id}")
    return vpc

# SUBNET - Figure 3 && Figure 4
def create_subnets(vpc):
    print("Subnets publics et privés")

    public_subnet_az1 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock=PUBLIC_SUBNET1_CIDR,
        AvailabilityZone=AZ1
    )
    public_subnet_az1.meta.client.modify_subnet_attribute(
        SubnetId=public_subnet_az1.id,
        MapPublicIpOnLaunch={"Value": True}
    )
    tag(public_subnet_az1, "public-az1")

    public_subnet_az2 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock=PUBLIC_SUBNET2_CIDR,
        AvailabilityZone=AZ2
    )
    public_subnet_az2.meta.client.modify_subnet_attribute(
        SubnetId=public_subnet_az2.id,
        MapPublicIpOnLaunch={"Value": True}
    )
    tag(public_subnet_az2, "public-az2")

    private_subnet_az1 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock=PRIVATE_SUBNET1_CIDR,
        AvailabilityZone=AZ1
    )
    tag(private_subnet_az1, "private-az1")

    private_subnet_az2 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock=PRIVATE_SUBNET2_CIDR,
        AvailabilityZone=AZ2
    )
    tag(private_subnet_az2, "private-az2")

    print("Subnets créés :")
    print(" Public AZ1 :", public_subnet_az1.id)
    print(" Public AZ2 :", public_subnet_az2.id)
    print(" Private AZ1:", private_subnet_az1.id)
    print(" Private AZ2:", private_subnet_az2.id)

    return (public_subnet_az1, public_subnet_az2,
            private_subnet_az1, private_subnet_az2)

# GETAWAY - Figure 5
def create_igw(vpc):
    print("Internet Gateway + attachment")
    igw = ec2.create_internet_gateway()
    tag(igw, "igw")

    vpc.attach_internet_gateway(InternetGatewayId=igw.id)
    print("Internet Gateway attaché :", igw.id)
    return igw

# GETAWAY - Figure 6
def create_nat_gateways(public_subnet_az1, public_subnet_az2):
    print("NAT Gateways")

    # EIP pour NAT AZ1
    eip1 = ec2_client.allocate_address(Domain="vpc")
    nat_gw1 = ec2_client.create_nat_gateway(
        SubnetId=public_subnet_az1.id,
        AllocationId=eip1["AllocationId"],
        TagSpecifications=[{
            "ResourceType": "natgateway",
            "Tags": [
                {"Key": "Name", "Value": f"{ENVIRONMENT_NAME}-nat-az1"},
                {"Key": "Environment", "Value": ENVIRONMENT_NAME},
            ],
        }]
    )
    nat_gw1_id = nat_gw1["NatGateway"]["NatGatewayId"]

    # EIP pour NAT AZ2
    eip2 = ec2_client.allocate_address(Domain="vpc")
    nat_gw2 = ec2_client.create_nat_gateway(
        SubnetId=public_subnet_az2.id,
        AllocationId=eip2["AllocationId"],
        TagSpecifications=[{
            "ResourceType": "natgateway",
            "Tags": [
                {"Key": "Name", "Value": f"{ENVIRONMENT_NAME}-nat-az2"},
                {"Key": "Environment", "Value": ENVIRONMENT_NAME},
            ],
        }]
    )
    nat_gw2_id = nat_gw2["NatGateway"]["NatGatewayId"]

    print("NAT Gateway AZ1 :", nat_gw1_id)
    print("NAT Gateway AZ2 :", nat_gw2_id)
    print("WAIT for NAT to be available...")

    waiter = ec2_client.get_waiter("nat_gateway_available")
    waiter.wait(NatGatewayIds=[nat_gw1_id, nat_gw2_id])

    print("NAT Gateways prêtes.")
    return nat_gw1_id, nat_gw2_id


# ROUTE : Figure 7 && Figure 8
def create_route_tables(vpc, igw,
                        public_subnet_az1, public_subnet_az2,
                        private_subnet_az1, private_subnet_az2,
                        nat_gw1_id, nat_gw2_id):
    print("Route tables publiques et privées")

    # Route table publique
    public_rt = ec2.create_route_table(VpcId=vpc.id)
    tag(public_rt, "public-rt")

    public_rt.create_route(
        DestinationCidrBlock="0.0.0.0/0",
        GatewayId=igw.id
    )

    public_rt.associate_with_subnet(SubnetId=public_subnet_az1.id)
    public_rt.associate_with_subnet(SubnetId=public_subnet_az2.id)

    # Route table privée AZ1 -> NAT AZ1
    private_rt_az1 = ec2.create_route_table(VpcId=vpc.id)
    tag(private_rt_az1, "private-rt-az1")

    private_rt_az1.create_route(
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=nat_gw1_id
    )

    private_rt_az1.associate_with_subnet(SubnetId=private_subnet_az1.id)

    # Route table privée AZ2 -> NAT AZ2
    private_rt_az2 = ec2.create_route_table(VpcId=vpc.id)
    tag(private_rt_az2, "private-rt-az2")

    private_rt_az2.create_route(
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=nat_gw2_id
    )

    private_rt_az2.associate_with_subnet(SubnetId=private_subnet_az2.id)

    print("Route table publique :", public_rt.id)
    print("Route table privée AZ1 :", private_rt_az1.id)
    print("Route table privée AZ2 :", private_rt_az2.id)

# SECURITY GROUP - Figure 9
def create_security_group(vpc):
    print("Security Group polystudent-sg1")

    sg = ec2.create_security_group(
        GroupName=f"{ENVIRONMENT_NAME}-sg",
        Description="polystudent security group for web/db access",
        VpcId=vpc.id
    )
    tag(sg, "sg1")

    # Autoriser les ports depuis n'importe où
    ip_permissions = []
    for port in INBOUND_PORTS:
        ip_permissions.append({
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })

    sg.authorize_ingress(IpPermissions=ip_permissions)

    print("Security group créé :", sg.id)
    return sg


#  VPC FLOW LOGS 
def create_vpc_flow_logs(vpc):
    """
    Crée un VPC Flow Log qui envoie UNIQUEMENT les paquets REJECT
    vers le bucket S3 spécifié.
    """
    print("Création du VPC Flow Log vers S3 (TrafficType=REJECT)...")

    try:
        resp = ec2_client.create_flow_logs(
            ResourceIds=[vpc.id],
            ResourceType="VPC",
            TrafficType="REJECT",            # <- seulement les paquets rejetés
            LogDestinationType="s3",
            LogDestination=S3_FLOW_LOG_ARN,  # arn du bucket S3
            MaxAggregationInterval=600,
            TagSpecifications=[
                {
                    "ResourceType": "vpc-flow-log",
                    "Tags": [
                        {"Key": "Name", "Value": f"{ENVIRONMENT_NAME}-vpc-flow-logs"},
                        {"Key": "Environment", "Value": ENVIRONMENT_NAME},
                    ],
                }
            ],
        )

        flow_log_ids = resp.get("FlowLogIds", [])
        if flow_log_ids:
            print("VPC Flow Log créé avec l’ID :", flow_log_ids[0])
        else:
            print("Aucun FlowLogId retourné, réponse brute :", resp)

    except ClientError as e:
        print("Erreur lors de la création des VPC Flow Logs :", e)


def main():
    try:
        vpc = create_vpc()
        (public_subnet_az1, public_subnet_az2,
         private_subnet_az1, private_subnet_az2) = create_subnets(vpc)

        igw = create_igw(vpc)
        nat_gw1_id, nat_gw2_id = create_nat_gateways(
            public_subnet_az1, public_subnet_az2
        )

        create_route_tables(
            vpc, igw,
            public_subnet_az1, public_subnet_az2,
            private_subnet_az1, private_subnet_az2,
            nat_gw1_id, nat_gw2_id
        )

        create_security_group(vpc)

        #  Appel pour créer les Flow Logs VPC 
        create_vpc_flow_logs(vpc)

        print("\n polystudentlab-vpc1 created + VPC Flow Logs configurés")
    except ClientError as e:
        print("Erreur AWS :", e)


if __name__ == "__main__":
    main()
