import boto3
from shutil import make_archive
from os import remove
from random import randrange


def run():
    REGIONS = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'sa-east-1', 'eu-west-1', 'eu-west-2',
               'eu-west-3', 'eu-central-1', 'ca-central-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
               'ap-southeast-2', 'ap-south-1']
    OUTPUT_FILENAME = 'GDPatrol'
    with open('role_policy.json', 'r') as rp:
        assume_role_policy = rp.read()
    zipped = make_archive(OUTPUT_FILENAME, 'zip', root_dir='GDPatrol')

    with open('lambda_policy.json', 'r') as lp:
        lambda_policy = lp.read()

    iam = boto3.client('iam')
    # delete the role if it already exists so it can be deployed with
    # the latest configuration
    roles = iam.list_roles()['Roles']
    for role in roles:
        if role['RoleName'] == 'GDPatrolRole':
            iam.delete_role_policy(RoleName='GDPatrolRole',
                                   PolicyName='GDPatrol_lambda_policy')
            iam.delete_role(RoleName='GDPatrolRole')

    created_role = iam.create_role(RoleName='GDPatrolRole',
                                   AssumeRolePolicyDocument=assume_role_policy)
    lambda_role_arn = created_role['Role']['Arn']

    iam.put_role_policy(RoleName='GDPatrolRole',
                        PolicyName='GDPatrol_lambda_policy',
                        PolicyDocument=lambda_policy)

    for region in REGIONS:

        lmb = boto3.client('lambda', region_name=region)
        cw_events = boto3.client('events', region_name=region)
        gd = boto3.client('guardduty', region_name=region)
        if not gd.list_detectors()['DetectorIds']:
            created_detector = gd.create_detector(Enable=True)
            print("Created GuardDuty detector: {}".format(created_detector['DetectorId']))
        else:
            gd.update_detector(DetectorId=gd.list_detectors()['DetectorIds'][0], Enable=True)
            print("Detector already exists: {}".format(gd.list_detectors()['DetectorIds'][0]))

        try:
            lmb.get_function(FunctionName='GDPatrol')
            lmb.delete_function(FunctionName='GDPatrol')
        except:
            pass
        lambda_response = lmb.create_function(FunctionName='GDPatrol',
                                       Runtime='python3.6',
                                       Role=lambda_role_arn,
                                       Handler='lambda_function.lambda_handler',
                                       Code={'ZipFile': open(zipped, 'rb').read()},
                                       Timeout=300, MemorySize=128)
        target_arn = lambda_response['FunctionArn']
        target_id = 'Id' + str(randrange(10 ** 11, 10 ** 12))


        # Remove targets and delete the CloudWatch rule before recreating it
        rules = cw_events.list_rules(NamePrefix='GDPatrol')['Rules']
        for rule in rules:
            if rule['Name'] == 'GDPatrol':
                targets = cw_events.list_targets_by_rule(Rule=rule['Name'])['Targets']
                for target in targets:
                    cw_events.remove_targets(Rule=rule['Name'], Ids=[target['Id']])
                cw_events.delete_rule(Name='GDPatrol')
        created_rule = cw_events.put_rule(Name='GDPatrol',
                                          EventPattern='{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}')
        cw_events.put_targets(Rule='GDPatrol',
                              Targets=[{'Id': target_id, 'Arn': target_arn, 'InputPath': '$.detail'}])

        # We are adding the trigger to the Lambda function so that it will be invoked every time  a finding is sent over
        statement_id = str(randrange(10 ** 11, 10 ** 12))
        lmb.add_permission(
            FunctionName=lambda_response['FunctionName'],
            StatementId=statement_id,
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=created_rule['RuleArn']
        )
        print("Successfully deployed the GDPatrol lambda function in region {}.".format(str(region)))
    remove(zipped)
if __name__ == '__main__':
    run()
