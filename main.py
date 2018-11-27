import argparse
import boto3
import ipaddress
import pprint


# argparse
parser = argparse.ArgumentParser()
parser.add_argument("source_ip", help="Source IP of the traffic")
parser.add_argument("destination_ip", help="Destination IP of the traffic")
parser.add_argument("port", help="Destination port of the traffic")
parser.add_argument("protocol", help="Protocol of the traffic (tcp, udp, icmp, or all)")
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
    port = int(args.port)
    protocol = args.protocol

    protocols = {
        "all": '-1',
        "icmp": '1',
        "tcp": '6',
        "udp": '17',
    }

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

    protocol_num = protocols[protocol]

    source_nacl_outbound_allowed = None
    source_nacl_inbound_allowed = None
    destination_nacl_inbound_allowed = None
    destination_nacl_outbound_allowed = None

    if source_subnet['VpcId'] == destination_subnet['VpcId']:
        # Source and destination are in the same VPC
        # Check to see if source_subnet NACL has egress rule to destination
        source_nacl_egress_rule_num_match = None  # NACL rule number that matches source IP
        source_nacl_inbound_rule_matched = False
        source_nacl_outbound_rule_matched = False
        # print(source_nacl_entries)

        for entry in source_nacl_entries:
            entry_cidr = ipaddress.IPv4Network(entry['CidrBlock'])
            port_range = None

            if destination_ip not in entry_cidr:
                print("Destination not in entry_cidr")
                continue

            if protocol_num != entry['Protocol']:
                print("Protocol does not match")
                continue

            try:
                entry['PortRange']
            except KeyError:
                present = False
            else:
                present = True

            if present and entry['Egress'] == True:
                start_port = entry['PortRange']['From']
                end_port = entry['PortRange']['To']
                #TODO - account for PortRange to be -1 to -1 aka ALL
                port_range = range(start_port, end_port + 1)

                if port not in port_range:
                    continue

            if present and entry['Egress'] == False:
                print("port range exists in entry and it's an ingress rule")
                start_port = entry['PortRange']['From']
                end_port = entry['PortRange']['To']
                high_ports = range(1024, 65536)
                if start_port not in high_ports or end_port not in high_ports:
                    continue


            else:
                # If 'PortRange' doesn't exist then I think it will be an ICMP entry and will
                # need to add additional logic to handle the IcmpTypeCode dict
                pass

            if source_nacl_outbound_rule_matched == False:
                if entry['RuleAction'] == 'allow' and entry['Egress'] == True:
                    print("source nacl outbound allowed")
                    source_nacl_outbound_rule_matched = True
                    source_nacl_outbound_allowed = True

                if entry['RuleAction'] == 'deny' and entry['Egress'] == True:
                    print("source nacl outbound not allowed")
                    source_nacl_outbound_rule_matched = True
                    source_nacl_outbound_allowed = False
                    break

            if source_nacl_inbound_rule_matched == False:
                if entry['RuleAction'] == 'allow' and entry['Egress'] == False:
                    print("source nacl inbound allowed")
                    source_nacl_inbound_rule_matched = True
                    source_nacl_inbound_allowed = True

                if entry['RuleAction'] == 'deny' and entry['Egress'] == False:
                    print(entry)
                    print("source nacl inbound not allowed")
                    source_nacl_inbound_rule_matched = True
                    source_nacl_inbound_allowed = False

                # if (destination_ip in entry_cidr and
                #     entry['Egress'] == True and
                #     entry['RuleAction'] == "allow" and
                #     entry['Protocol'] == protocol_num and
                #     port in port_range):

                #     source_nacl_egress_rule_num_match = entry['RuleNumber']
                #     break

        if source_nacl_outbound_allowed == True and source_nacl_inbound_allowed == True:
            print("Source NACLs allow this traffic")

        else:
            print("Source NACLs do not allow this traffic")

        # if source_nacl_egress_rule_num_match == None:
        #     print("Source outbound NACL will not allow this traffic")
        #     return
        # else:
        #     print(f"NACL rule number {source_nacl_egress_rule_num_match} will allow this traffic")
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
