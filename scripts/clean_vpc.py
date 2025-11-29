import boto3
from botocore.exceptions import ClientError

REGION = "ca-central-1"
ENVIRONMENT_NAME = "polystudent"  

ec2 = boto3.client("ec2", region_name=REGION)

def get_vpcs():
    resp = ec2.describe_vpcs(
        Filters=[{"Name": "tag:Environment", "Values": [ENVIRONMENT_NAME]}]
    )
    return [v["VpcId"] for v in resp["Vpcs"]]

def delete_nat_gateways(vpc_id):
    resp = ec2.describe_nat_gateways(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    for gw in resp.get("NatGateways", []):
        gw_id = gw["NatGatewayId"]
        print(f"  Suppression NAT Gateway {gw_id}...")
        try:
            ec2.delete_nat_gateway(NatGatewayId=gw_id)
        except ClientError as e:
            print("    ERREUR delete_nat_gateway:", e)

        # libère les EIP associés
        for addr in gw.get("NatGatewayAddresses", []):
            alloc_id = addr.get("AllocationId")
            if alloc_id:
                print(f"    Release EIP {alloc_id}...")
                try:
                    ec2.release_address(AllocationId=alloc_id)
                except ClientError as e:
                    print("      ERREUR release_address:", e)

def delete_internet_gateways(vpc_id):
    resp = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    )
    for igw in resp.get("InternetGateways", []):
        igw_id = igw["InternetGatewayId"]
        print(f"  Detach & delete IGW {igw_id}...")
        try:
            ec2.detach_internet_gateway(
                InternetGatewayId=igw_id,
                VpcId=vpc_id
            )
        except ClientError as e:
            print("    ERREUR detach_igw:", e)
        try:
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as e:
            print("    ERREUR delete_igw:", e)

def delete_route_tables(vpc_id):
    resp = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "tag:Environment", "Values": [ENVIRONMENT_NAME]},
        ]
    )
    for rt in resp.get("RouteTables", []):
        rt_id = rt["RouteTableId"]
        # supprimer les associations non-main
        for assoc in rt.get("Associations", []):
            if not assoc.get("Main", False):
                assoc_id = assoc["RouteTableAssociationId"]
                print(f"  Suppression association route {assoc_id}...")
                try:
                    ec2.disassociate_route_table(
                        AssociationId=assoc_id
                    )
                except ClientError as e:
                    print("    ERREUR disassociate:", e)
        print(f"  Suppression route table {rt_id}...")
        try:
            ec2.delete_route_table(RouteTableId=rt_id)
        except ClientError as e:
            print("    ERREUR delete_route_table:", e)

def delete_subnets(vpc_id):
    resp = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "tag:Environment", "Values": [ENVIRONMENT_NAME]},
        ]
    )
    for sn in resp.get("Subnets", []):
        sn_id = sn["SubnetId"]
        print(f"  Suppression subnet {sn_id}...")
        try:
            ec2.delete_subnet(SubnetId=sn_id)
        except ClientError as e:
            print("    ERREUR delete_subnet:", e)

def delete_security_groups(vpc_id):
    resp = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    for sg in resp.get("SecurityGroups", []):
        if sg["GroupName"] == "default":
            continue
        sg_id = sg["GroupId"]
        print(f"  Suppression security group {sg_id} ({sg['GroupName']})...")
        try:
            ec2.delete_security_group(GroupId=sg_id)
        except ClientError as e:
            print("    ERREUR delete_sg:", e)

def delete_vpc(vpc_id):
    print(f"Suppression du VPC {vpc_id}...")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as e:
        print("  ERREUR delete_vpc:", e)

def main():
    vpcs = get_vpcs()
    if not vpcs:
        print(f"Aucun VPC ={ENVIRONMENT_NAME}")
        return

    for vpc_id in vpcs:
        print(f"\n=== Nettoyage du VPC {vpc_id} ===")
        delete_nat_gateways(vpc_id)
        delete_internet_gateways(vpc_id)
        delete_route_tables(vpc_id)
        delete_subnets(vpc_id)
        delete_security_groups(vpc_id)
        delete_vpc(vpc_id)

    print("\nNettoyage terminé.")

if __name__ == "__main__":
    main()
