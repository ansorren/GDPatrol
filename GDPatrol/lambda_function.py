import boto3
import uuid
import json
from socket import gethostbyname, gaierror
from inspect import stack
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def blacklist_ip(ip_address):
    try:
        client = boto3.client('ec2')
        nacls = client.describe_network_acls()
        for nacl in nacls["NetworkAcls"]:
            min_rule_id = min(
                rule['RuleNumber'] for rule in nacl["Entries"] if not rule["Egress"]
            )
            if min_rule_id < 1:
                raise Exception("Rule number is less than 1")
            r = client.create_network_acl_entry(
                CidrBlock='{}/32'.format(ip_address),
                Egress=False,
                NetworkAclId=nacl["NetworkAclId"],
                Protocol='-1',
                RuleAction='deny',
                RuleNumber=min_rule_id - 1,
            )
            logger.info("GDPatrol: Successfully executed action {} for ".format(
                stack()[0][3], ip_address))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))


def whitelist_ip(ip_address):
    try:
        client = boto3.client('ec2')
        nacls = client.describe_network_acls()
        for nacl in nacls["NetworkAcls"]:
            for rule in nacl["Entries"]:
                if rule["CidrBlock"] == '{}/32'.format(ip_address):
                    client.delete_network_acl_entry(
                        NetworkAclId=nacl["NetworkAclId"],
                        Egress=rule["Egress"],
                        RuleNumber=rule["RuleNumber"]
                        )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], ip_address))
        return True

    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


def quarantine_instance(instance_id, vpc_id):
    try:
        client = boto3.client('ec2')
        sg = client.create_security_group(
            GroupName='Quarantine-{}'.format(str(uuid.uuid4().fields[-1])[:6]),
            Description='Quarantine for {}'.format(instance_id),
            VpcId=vpc_id
        )
        sg_id = sg["GroupId"]

        # NOTE: Remove the default egress group
        client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'FromPort': 0,
                    'ToPort': 65535,
                    'IpRanges': [
                        {
                            'CidrIp': "0.0.0.0/0"
                        },
                    ]
                }
            ]
        )


        # NOTE: Assign security group to instance
        client.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])


        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], instance_id))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


def snapshot_instance(instance_id):
    try:
        client = boto3.client('ec2')
        instance_described = client.describe_instances(InstanceIds=[instance_id])
        blockmappings = instance_described['Reservations'][0]['Instances'][0]['BlockDeviceMappings']
        for device in blockmappings:
            snapshot = client.create_snapshot(
                VolumeId=device["Ebs"]["VolumeId"],
                Description="Created by GDpatrol for {}".format(instance_id)
            )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], instance_id))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False

def disable_account(username):
    try:
        client = boto3.client('iam')
        client.put_user_policy(
            UserName=username,
            PolicyName='BlockAllPolicy',
            PolicyDocument="{\"Version\":\"2012-10-17\", \"Statement\""
                           ":{\"Effect\":\"Deny\", \"Action\":\"*\", "
                           "\"Resource\":\"*\"}}"
        )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], username))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


def disable_ec2_access(username):
    try:
        client = boto3.client('iam')
        client.put_user_policy(
            UserName=username,
            PolicyName='BlockEC2Policy',
            PolicyDocument="{\"Version\":\"2012-10-17\", \"Statement\""
                           ":{\"Effect\":\"Deny\", \"Action\":\"ec2:*\" , "
                           "\"Resource\":\"*\"}}"
                           )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], username))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False

def enable_ec2_access(username):
    try:
        client = boto3.client('iam')
        client.delete_user_policy(
            UserName=username,
            PolicyName='BlockEC2Policy',
        )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], username))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


def disable_sg_access(username):
    try:
        client = boto3.client('iam')
        client.put_user_policy(
            UserName=username,
            PolicyName='BlockSecurityGroupPolicy',
            PolicyDocument="{\"Version\":\"2012-10-17\", \"Statement\""
                           ":{\"Effect\":\"Deny\", \"Action\": [ "
                           "\"ec2:AuthorizeSecurityGroupIngress\", "
                           "\"ec2:RevokeSecurityGroupIngress\", "
                           "\"ec2:AuthorizeSecurityGroupEgress\", "
                           "\"ec2:RevokeSecurityGroupEgress\" ], "
                           "\"Resource\":\"*\"}}"
        )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], username))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


def enable_sg_access(username):
    try:
        client = boto3.client('iam')
        client.delete_user_policy(
            UserName=username,
            PolicyName='BlockSecurityGroupPolicy',
        )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], username))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


def asg_detach_instance(instance_id):
    try:
        client = boto3.client('autoscaling')
        response = client.describe_auto_scaling_instances(
            InstanceIds=[instance_id],
            MaxRecords=1
        )
        asg_name = None
        instances = response['AutoScalingInstances']
        if instances:
            asg_name = instances[0]['AutoScalingGroupName']

        if asg_name is not None:
            response = client.detach_instances(
                InstanceIds=[instance_id],
                AutoScalingGroupName=asg_name,
                ShouldDecrementDesiredCapacity=False
            )
        logger.info("GDPatrol: Successfully executed action {} for {}".format(stack()[0][3], instance_id))
        return True
    except Exception as e:
        logger.error("GDPatrol: Error executing {} - {}".format(stack()[0][3], e))
        return False


class Config(object):
    def __init__(self, finding_type):
        self.finding_type = finding_type
        self.actions = []
        self.reliability = 0


    def get_actions(self):
        with open('config.json', 'r') as config:
            jsonloads = json.loads(config.read())
            for item in jsonloads['playbooks']['playbook']:
                if item['type'] == self.finding_type:
                    self.actions = item['actions']
                    return self.actions

    def get_reliability(self):
        with open('config.json', 'r') as config:
            jsonloads = json.loads(config.read())
            for item in jsonloads['playbooks']['playbook']:
                if item['type'] == self.finding_type:
                    self.reliability = int(item['reliability'])
                    return self.reliability


def lambda_handler(event, context):
    logger.info("GDPatrol: Received JSON event - ".format(event))
    try:

        finding_id = event['id']
        finding_type =  event['type']
        logger.info("GDPatrol: Parsed Finding ID: {} - Finding Type: {}".format(finding_id, finding_type))
        config = Config(event['type'])
        severity = int(event['severity'])

        config_actions = config.get_actions()
        config_reliability = config.get_reliability()
        resource_type = event['resource']['resourceType']
    except KeyError as e:
        logger.error("GDPatrol: Could not parse the Finding fields correctly, please verify that the JSON is correct")
        exit(1)
    if resource_type == 'Instance':
        instance = event['resource']['instanceDetails']
        instance_id = instance["instanceId"]
        vpc_id = instance['networkInterfaces'][0]['vpcId']
    elif resource_type == 'AccessKey':
        username = event['resource']['accessKeyDetails']['userName']

    if event['service']['action']['actionType'] == 'DNS_REQUEST':
        domain = event['service']['action']['dnsRequestAction']['domain']
    elif event['service']['action']['actionType'] == 'AWS_API_CALL':
        ip_address = event['service']['action']['awsApiCallAction']['remoteIpDetails']['ipAddressV4']
    elif event['service']['action']['actionType'] == 'NETWORK_CONNECTION':
        ip_address = event['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']
    elif event['service']['action']['actionType'] == 'PORT_PROBE':
        ip_address = event['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails']['ipAddressV4']

    successful_actions = 0
    total_config_actions = len(config_actions)
    actions_to_be_executed = 0
    for action in config_actions:
        logger.info("GDPatrol: Action: {}".format(action))
        if action == 'blacklist_ip':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = blacklist_ip(ip_address)
                successful_actions += int(result)
        elif action == 'whitelist_ip':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = whitelist_ip(ip_address)
                successful_actions += int(result)
        elif action == 'blacklist_domain':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                try:
                    ip_address = gethostbyname(domain)
                    result = blacklist_ip(ip_address)
                    successful_actions += int(result)
                except gaierror as e:
                    logger.error("GDPatrol: Error resolving domain {} - {}".format(domain, e))
                    pass
        elif action == 'quarantine_instance':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = quarantine_instance(instance_id, vpc_id)
                successful_actions += int(result)
        elif action == 'snapshot_instance':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = snapshot_instance(instance_id)
                successful_actions += int(result)
        elif action == 'disable_account':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = disable_account(username)
                successful_actions += int(result)
        elif action == 'disable_ec2_access':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = disable_ec2_access(username)
                successful_actions += int(result)
        elif action == 'enable_ec2_access':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = enable_ec2_access(username)
                successful_actions += int(result)
        elif action == 'disable_sg_access':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = disable_sg_access(username)
                successful_actions += int(result)
        elif action == 'enable_sg_access':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = enable_sg_access(username)
                successful_actions += int(result)
        elif action == 'asg_detach_instance':
            if severity + config_reliability > 10:
                actions_to_be_executed += 1
                logger.info("GDPatrol: Executing action {}".format(action))
                result = asg_detach_instance(instance_id)
                successful_actions += int(result)
    logger.info("GDPatrol: Total actions: {} - Actions to be executed: {} - Successful Actions: {} - Finding ID:  {} - Finding Type: {}".format(
                total_config_actions, actions_to_be_executed, successful_actions, finding_id, finding_type))
