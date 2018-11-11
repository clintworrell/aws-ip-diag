import boto3
import ipaddress
import pprint

pp = pprint.PrettyPrinter()

client = boto3.client('ec2')

vpcs = client.describe_vpcs()['Vpcs']


def detect_vpc(ip):
    for vpc in vpcs:
        vpc_cidr = ipaddress.IPv4Network(vpc['CidrBlock'])
        vpc_name = get_vpc_name_tag(vpc)
        ip = ipaddress.IPv4Address(ip)

        if ip in vpc_cidr:
            print(f"{str(ip)} is in {str(vpc_cidr)} ({vpc_name})")
            break
        else:
            print(f"{str(ip)} is not in {str(vpc_cidr)}")


def get_vpc_name_tag(vpc):
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


detect_vpc("10.20.48.231")
detect_vpc("172.31.25.149")
