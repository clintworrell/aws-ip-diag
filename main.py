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

    return subnets


def get_subnet(vpc_subnets, ip):
    for vpc_subnet in vpc_subnets['Subnets']:
        subnet_cidr = ipaddress.IPv4Network(vpc_subnet['CidrBlock'])

        if ip in subnet_cidr:
            subnet = vpc_subnet
            break

    return subnet


def get_nacl(subnet):
    subnet_id = subnet['SubnetId']
    nacl = ec2.describe_network_acls(
        Filters = [
            {
                'Name': 'association.subnet-id',
                'Values': [
                    subnet_id,
                ]
            }
        ]
    )

    return nacl


def main():
    source_ip = ipaddress.IPv4Address(args.source_ip)
    destination_ip = ipaddress.IPv4Address(args.destination_ip)

    source_vpc_id = get_vpc(source_ip)
    destination_vpc_id = get_vpc(destination_ip)

    # Get the subnets of the VPCs
    if source_vpc_id and destination_vpc_id:
        print("Source and destination are in VPCs...")
        source_vpc_subnets = get_vpc_subnets(source_vpc_id)
        destination_vpc_subnets = get_vpc_subnets(destination_vpc_id)
        vpc_subnets = [source_vpc_subnets, destination_vpc_subnets]
    else:
        print("Source and/or destination are not in a VPC")
        return

    # Get the subnet of source and destination
    if source_vpc_subnets and destination_vpc_subnets:
        source_subnet = get_subnet(source_vpc_subnets, source_ip)
        destination_subnet = get_subnet(destination_vpc_subnets, destination_ip)
    else:
        print("Source and/or destination VPC does not have any subnets")
        return

    # Get the NACLs
    if source_subnet and destination_subnet:
        source_nacl = get_nacl(source_subnet)
        destination_nacl = get_nacl(destination_subnet)

        # Get NACL entries and sort them by rule number
        source_nacl_entries = source_nacl['NetworkAcls'][0]['Entries']
        source_nacl_entries = sorted(source_nacl_entries, key=lambda x: x['RuleNumber'])

        destination_nacl_entries = destination_nacl['NetworkAcls'][0]['Entries']
        destination_nacl_entries = sorted(destination_nacl_entries, key=lambda x: x['RuleNumber'])
    else:
        print("Source and/or destination VPC does not have a subnet matching the IP provided")
        return

    if source_subnet['VpcId'] == destination_subnet['VpcId']:
        # Source and destination are in the same VPC
        # Check to see if source_subnet NACL has egress rule to destination
        source_nacl_egress_rule_num_match = None  # NACL rule number that matches source IP

        for entry in source_nacl_entries:
            if (destination_ip in ipaddress.IPv4Network(entry['CidrBlock']) and
                entry['Egress'] == True and
                entry['RuleAction'] == "allow"):
                source_nacl_egress_rule_num_match = entry['RuleNumber']
                break

        if source_nacl_egress_rule_num_match == None:
            print("Source outbound NACL will not allow this traffic")
            return
        else:
            print(f"NACL rule number {source_nacl_egress_rule_num_match} will allow this traffic")

        # Check that NACLs allow traffic to itself
        # Check subnets allow egress from source to dest and allow ingress from source to dest
    else:
        # Check peering
        # Check routes
        # Check NACLs (inbound and outbound on both source and destination)
        # Check security groups

        pass

if __name__ == "__main__":
    main()
