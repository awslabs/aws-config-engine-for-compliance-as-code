import sys
import json
import re
import time
import boto3

template_bucket_name = sys.argv[1]
default_template_name = "default.json"
remote_execution_role_name = "AWSConfigAndComplianceAuditRole-DO-NOT-DELETE"
remote_execution_path_name = "service-role/"
stack_name = "Compliance-Engine-Benchmark-DO-NOT-DELETE"
initial_deployed_rule = "COMPLIANCE_RULESET_LATEST_INSTALLED"

central_sts_client = boto3.client('sts')
central_account_id = central_sts_client.get_caller_identity()["Account"]

s3 = boto3.resource('s3')
s3_client = boto3.client('s3')

default_template_obj = s3.Object(template_bucket_name, default_template_name)
default_template = json.loads(default_template_obj.get()['Body'].read().decode('utf-8'))

contents = s3_client.list_objects(Bucket=template_bucket_name)['Contents']
list_of_account_to_review = []

for s3_object in contents:
    #Assumes S3 template keys are of the form <12-digit-account-id>.json
    key = s3_object["Key"]

    if not re.match('^[0-9]{12}\.json$', key):
        #Skip this one
        print("Skipping " + key)
        continue

    remote_account_id = key.split(".")[0]

    obj = s3.Object(template_bucket_name, key)
    template = obj.get()['Body'].read().decode('utf-8')

    #Check if the remote Rule template is empty.  If it is, use the default Rule template.
    #template_key = key
    if not template:
        default_obj = s3.Object(template_bucket_name, default_template_name)
        template = default_obj.get()['Body'].read().decode('utf-8')

    remote_session = None
    try:
        remote_sts_client = boto3.client('sts')
        response = remote_sts_client.assume_role(
            RoleArn='arn:aws:iam::'+remote_account_id+':role/' + remote_execution_path_name + remote_execution_role_name,
            RoleSessionName='ComplianceAutomationSession'
            )

        remote_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
    except Exception as e3:
        print("Failed to assume role into remote account. " + str(e3))
        continue

    cfn = remote_session.client("cloudformation")
    try:
        print("Attempting to update Rule stack.")
        update_response = cfn.update_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[
                {
                    'ParameterKey': 'LambdaAccountId',
                    'ParameterValue': central_account_id
                }
            ],
            Capabilities=['CAPABILITY_NAMED_IAM']
        )
        print("Update triggered for " + remote_account_id + ".")
        list_of_account_to_review.append(remote_account_id)
    except Exception as e:
        if "No updates are to be performed." in str(e):
            print("Stack already up-to-date.")
            continue

        if "does not exist" in str(e):
            try:
                print("Stack not found. Attempting to create Rule stack.")
                create_response = cfn.create_stack(
                    StackName=stack_name,
                    TemplateBody=template,
                    Parameters=[
                        {
                            'ParameterKey': 'LambdaAccountId',
                            'ParameterValue': central_account_id
                        }
                    ],
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
                print("Creation triggered for " + remote_account_id + ".")
                list_of_account_to_review.append(remote_account_id)
                continue
            except Exception as e2:
                print("Error creating new stack: " + str(e2))

        print("Error no condition matched: " + str(e))

if not list_of_account_to_review:
    sys.exit(0)

time.sleep(20)

for remote_account_id in list_of_account_to_review:
    remote_session = None
    try:
        remote_sts_client = boto3.client('sts')
        response = remote_sts_client.assume_role(
            RoleArn='arn:aws:iam::'+remote_account_id+':role/' + remote_execution_path_name + remote_execution_role_name,
            RoleSessionName='ComplianceAutomationTriggerRuleSession'
            )

        remote_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
    except Exception as e3:
        print("Failed to assume role into remote account. " + str(e3))
        continue

    config_client = remote_session.client("config")
    try:
        print("Attempting to trigger the crawler Rule.")
        config_client.start_config_rules_evaluation(ConfigRuleNames=[initial_deployed_rule])
    except Exception as e:
        print("Error when triggering the crawler Rule: " + str(e))

sys.exit(0)
