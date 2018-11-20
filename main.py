import argparse
import boto3
import ipaddress
import pprint

# argparse
parser = argparse.ArgumentParser()
parser.add_argument("source_ip", help="Source IP of the traffic")
parser.add_argument("destination_ip", help="Destination IP of the traffic")
args = parser.parse_args()
print(f"Checking if {args.source_ip} and {args.destination_ip} are in VPCs...")

ec2 = boto3.client('ec2')

# Determine if IP is part of a VPC CIDR
def get_vpc(ip):
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        vpc_cidr = ipaddress.IPv4Network(vpc['CidrBlock'])
        vpc_name = get_vpc_name(vpc)
        vpc_id = vpc['VpcId']

        if ip in vpc_cidr:
            return vpc_id
        else:
            return None


def get_vpc_name(vpc):
    try:
        vpc['Tags'][0]['Value']
    except KeyError:
        present = False
    else:
        present = True

    if present:
        vpc_name = vpc['Tags'][0]['Value']
    else:
        vpc_name = "VPC name tag missing"

    return vpc_name


def get_vpc_subnets(vpc_id):
    subnets = ec2.describe_subnets(
        Filters = [
            {
                'Name': 'vpc-id',
                'Values': [
                    vpc_id,
                ]
            },
        ]
    )

    # subnets = subnets['Subnets']

    return subnets


def main():
    source_ip = ipaddress.IPv4Address(args.source_ip)
    destination_ip = ipaddress.IPv4Address(args.destination_ip)
    ips = [source_ip, destination_ip]

    source_vpc_id = get_vpc(source_ip)
    destination_vpc_id = get_vpc(destination_ip)
    vpc_ids = [source_vpc_id, destination_vpc_id]

    if source_vpc_id and destination_vpc_id:
        print("Source and destination are in VPCs...")
        source_vpc_subnets = get_vpc_subnets(source_vpc_id)
        print(source_vpc_subnets)
        destination_vpc_subnets = get_vpc_subnets(destination_vpc_id)
        vpc_subnets = [source_vpc_subnets, destination_vpc_subnets]

    # Identify source and destination subnets
    # Should be refactored later
    for subnet in source_vpc_subnets['Subnets']:
        subnet_cidr = ipaddress.IPv4Network(subnet['CidrBlock'])
        if source_ip in subnet_cidr:
            source_subnet = subnet
            print(source_subnet)
            break
        else:
            source_subnet = None
            print("Source IP isn't in a subnet")

    for subnet in destination_vpc_subnets['Subnets']:
        subnet_cidr = ipaddress.IPv4Network(subnet['CidrBlock'])
        if destination_ip in subnet_cidr:
            destination_subnet = subnet
            print(destination_subnet)
            break
        else:
            destination_subnet = None
            print("Destination IP isn't in a subnet")

    # Identify NACLs associated with the source and destination subnets
    if source_subnet and destination_subnet:
        if source_subnet['VpcId'] != destination_subnet['VpcId']:
            # Check peering
            # Check routes
            # Check NACLs (inbound and outbound on both source and destination)
            # Check security groups
            pass
        else:
            # Source and destination are in the same VPC
            # Check that source_subnet NACL has egress rule to destination subnet
            source_subnet_id = source_subnet['SubnetId']
            source_subnet_nacl = ec2.describe_network_acls(
                Filters = [
                    {
                        'Name': 'association.subnet-id',
                        'Values': [
                            source_subnet_id,
                        ]
                    }
                ]
            )
            print(source_subnet_nacl)
            print(source_subnet_id)
            # Check that NACLs allow traffic to itself
            # Check subnets allow egress from source to dest and allow ingress from source to dest
            pass

if __name__ == "__main__":
    main()
