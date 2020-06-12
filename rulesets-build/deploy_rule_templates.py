import sys
import json
import re
import time
import boto3
import add_rule_tags

main_region = sys.argv[1]
template_bucket_name_prefix = sys.argv[2]
initial_deployed_rule = sys.argv[3]
other_regions = sys.argv[4]
remote_execution_role_name = sys.argv[5]
remote_execution_path_name = sys.argv[6]
stack_name = sys.argv[7]
default_template_name = "default.json"
default_rule_tags_script_suffix = "_rule_tags.sh"

central_sts_client = boto3.client('sts')
central_account_id = central_sts_client.get_caller_identity()["Account"]

all_region_list = []
all_region_list.append(main_region)
if other_regions != 'none':
    other_regions_list = other_regions.split(',')
    all_region_list += other_regions_list

s3 = boto3.resource('s3')
s3_client = boto3.client('s3')

for region in all_region_list:
    template_bucket_name = template_bucket_name_prefix + '-' + region
    default_template_obj = s3.Object(template_bucket_name, default_template_name)
    default_template = json.loads(default_template_obj.get()['Body'].read().decode('utf-8'))

    contents = s3_client.list_objects(Bucket=template_bucket_name)['Contents']
    list_of_account_to_review = []

    for s3_object in contents:
        #Assumes S3 template keys are of the form <12-digit-account-id>.json
        key = s3_object["Key"]

        if not re.match('^[0-9]{12}\.json$', key):
            #Skip this one
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

        cfn = remote_session.client("cloudformation", region_name=region)
        print("Start rules deployment on account {} for region {}.".format(remote_account_id, region))
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
            elif "does not exist" in str(e):
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
                except Exception as e2:
                    print("Error creating new stack: " + str(e2))
            else:
                print("Error no condition matched: " + str(e))

        #tagging config rules
        add_rule_tags.execute_add_rule_tags_script(template_bucket_name, remote_account_id, default_rule_tags_script_suffix, remote_session, s3_client)

    if not list_of_account_to_review:
        continue

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

        config_client = remote_session.client("config", region_name=region)
        try:
            print("Attempting to trigger the crawler Rule.")
            config_client.start_config_rules_evaluation(ConfigRuleNames=[initial_deployed_rule])
        except Exception as e:
            print("Error when triggering the crawler Rule: " + str(e))

sys.exit(0)
