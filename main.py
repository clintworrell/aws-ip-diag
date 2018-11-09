import boto3
import ipaddress
import pprint

pp = pprint.PrettyPrinter()

client = boto3.client('ec2')
response = client.describe_vpcs()

vpcs = response['Vpcs']
if vpcs:
    for vpc in vpcs:
        if 'Tags' in vpc:
            pp.pprint(vpc['CidrBlock'] + ' > ' + vpc['Tags'][0]['Value'])
        else:
            pp.pprint(vpc['CidrBlock'])
        print(ipaddress.IPv4Address('10.20.48.231') in ipaddress.IPv4Network(vpc['CidrBlock']))
else:
    print('No VPCs found')
