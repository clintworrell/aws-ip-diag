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
        # print(source_vpc_subnets)
        destination_vpc_subnets = get_vpc_subnets(destination_vpc_id)
        vpc_subnets = [source_vpc_subnets, destination_vpc_subnets]
    else:
        return

    # Identify source and destination subnets
    # Should be refactored later
    source_subnet = None
    for subnet in source_vpc_subnets['Subnets']:
        subnet_cidr = ipaddress.IPv4Network(subnet['CidrBlock'])

        if source_ip in subnet_cidr:
            source_subnet = subnet
            break

    if source_subnet == None:
        print("Source IP isn't in a subnet")
        return

    destination_subnet = None
    for subnet in destination_vpc_subnets['Subnets']:
        subnet_cidr = ipaddress.IPv4Network(subnet['CidrBlock'])
        if destination_ip in subnet_cidr:
            destination_subnet = subnet
            # print(destination_subnet)
            break
    if destination_subnet == None:
        print("Destination IP isn't in a subnet")
        return

    # Identify NACLs associated with the source and destination subnets
    if source_subnet and destination_subnet:
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

        destination_subnet_id = destination_subnet['SubnetId']
        destination_subnet_nacl = ec2.describe_network_acls(
            Filters = [
                {
                    'Name': 'association.subnet-id',
                    'Values': [
                        destination_subnet_id,
                    ]
                }
            ]
        )

        # print(source_subnet_nacl)

        # Get NACL entries
        source_nacl_entries = source_subnet_nacl['NetworkAcls'][0]['Entries']
        source_nacl_entries = sorted(source_nacl_entries, key=lambda x: x['RuleNumber'])

        destination_nacl_entries = destination_subnet_nacl['NetworkAcls'][0]['Entries']
        destination_nacl_entries = sorted(destination_nacl_entries, key=lambda x: x['RuleNumber'])

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
