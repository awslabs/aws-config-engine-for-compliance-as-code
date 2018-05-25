#
# Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

import json
from datetime import datetime
import traceback
import sys
import boto3

S3_CLIENT = boto3.client('s3')
LOCAL_CONFIG_CLIENT = boto3.client('config')
STS_SESSION = None

# DEFINE SNS TOPIC
SNS_TOPIC_ARN = ''

# DEFINE CLOUDFORMATION S3 LOCATION
# This controls enables the Compliance Validation of the Current deployment by verifying if the latest CFn template is deployed in the Application account. Add the cfn file in a specific bucket in the Compliance Account.
CFN_APP_RULESET_STACK_NAME = ''
CFN_APP_RULESET_S3_BUCKET = ''
CFN_APP_RULESET_TEMPLATE_NAME = ''

# DEFINE WHITELIST LOCATION
# This parameters allows you to overwrite a compliance status before it got pushed into the Compliance Data Lake, via Firehose.
WHITELIST_S3_BUCKET = ''
WHITELIST_S3_KEY = 'compliance-whitelist.json'

# DEFINE NAME OF THE CONFIG AGGREGATOR
# This parameter is naming the Config Aggregator to be set up for all new accounts.
CONFIG_AGGREG_NAME = 'Compliance-Automation-Aggregator'

def get_sts_session(event, rolename):
    global STS_SESSION
    sts_local_client = boto3.client("sts")
    response = sts_local_client.assume_role(
        RoleArn=str("arn:aws:iam::" + event['configRuleArn'].split(":")[4] + ":role/" + rolename),
        RoleSessionName='ComplianceAudit',
        DurationSeconds=900)
    STS_SESSION = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
        region_name=event['configRuleArn'].split(":")[3],
        botocore_session=None,
        profile_name=None)

def send_results_to_sns(result_detail, accountID, timestamp):
    region = (SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
    client = boto3.client('sns', region_name=region)
    result_detail = json.dumps(result_detail, default=datetime_handler)
    messagejson = json.dumps({'default': result_detail})
    client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="Non-compliant resource detected in " + accountID + " at " + timestamp,
        Message=messagejson,
        MessageStructure='json'
    )
    print("SNS Topic triggered")

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")

def validate_if_latest_cfn():

    cfn_client = STS_SESSION.client('cloudformation')

    object_cfn = S3_CLIENT.get_object(Bucket=CFN_APP_RULESET_S3_BUCKET, Key=CFN_APP_RULESET_TEMPLATE_NAME)
    expected_template = object_cfn["Body"].read().decode("utf-8")

    running_template = cfn_client.get_template(StackName=CFN_APP_RULESET_STACK_NAME)['TemplateBody']

    ex_template = ''.join([line.rstrip()+'\n' for line in expected_template.splitlines()])
    run_template = ''.join([line.rstrip()+'\n' for line in running_template.splitlines()])

    parameter_list = []

    for param in cfn_client.describe_stacks(StackName=CFN_APP_RULESET_STACK_NAME)['Stacks'][0]['Parameters']:
        parameter_list.append(
            {
                'ParameterKey': param['ParameterKey'],
                'UsePreviousValue': True
            })

    if ex_template == run_template:
        return {
            "Annotation" : "This account runs the latest Compliance-as-code stack.",
            "ComplianceType" : "COMPLIANT"
            }
    return {
        "Annotation" : "This account is not running the latest Compliance-as-code stack. Contact the Security team.",
        "ComplianceType" : "NON_COMPLIANT"
        }

def is_compliance_result_whitelisted(result):
    if not WHITELIST_S3_BUCKET or not WHITELIST_S3_KEY:
        return False

    object_wl = S3_CLIENT.get_object(Bucket=WHITELIST_S3_BUCKET, Key=WHITELIST_S3_KEY)
    whitelist_json = json.loads(object_wl["Body"].read().decode("utf-8"))

    for whitelist_item in whitelist_json["Whitelist"]:
        if whitelist_item["RuleARN"] == result["RuleARN"]:
            for whitelisted_resources in whitelist_item["WhitelistedResources"]:
                if result["ResourceId"] in whitelisted_resources["ResourceIds"] \
                and whitelisted_resources["ApprovalTicket"] \
                and datetime.today().date() <= datetime.strptime(whitelisted_resources["ValidUntil"], '%Y-%m-%d').date():
                    print(result["ResourceId"] + " whitelisted for " + result["RuleARN"] + ".")
                    return True
    return False

def enable_config_aggregator(account_id):
    if not is_config_aggregator_set_up(account_id):
        LOCAL_CONFIG_CLIENT.put_configuration_aggregator(
            ConfigurationAggregatorName=CONFIG_AGGREG_NAME,
            AccountAggregationSources=[
                {
                    'AccountIds': [account_id],
                    'AllAwsRegions': True
                }
            ])

def is_config_aggregator_set_up(account_id):
    try:
        aggreg_details = LOCAL_CONFIG_CLIENT.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[CONFIG_AGGREG_NAME])
    except:
        return False

    for source in aggreg_details['ConfigurationAggregators'][0]['AccountAggregationSources']:
        for account in source['AccountIds']:
            if account == account_id and source['AllAwsRegions']:
                return True
    return False

def lambda_handler(event, context):

    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event["ruleParameters"])

    # Assume Role to get access to the application account information via sts session named STS_SESSION
    get_sts_session(event, rule_parameters["RoleToAssume"])

    enable_config_aggregator(invoking_event['awsAccountId'])

    result_token = "No token found."

    if "resultToken" in event:
        result_token = event["resultToken"]

    config = STS_SESSION.client('config')

    config_all_rules = config.describe_config_rules()
    # print(config_all_rules)

    for ConfigRules in config_all_rules["ConfigRules"]:

        rule_compliance_details = config.get_compliance_details_by_config_rule(ConfigRuleName=ConfigRules["ConfigRuleName"], Limit=100)

        # Skip this rule in the result
        if ConfigRules["ConfigRuleId"] == event['configRuleId']:
            continue

        kinesis_client = boto3.client("firehose")

        while True:
            for ResultIdentifiers in rule_compliance_details['EvaluationResults']:
                timestamp_now = str(datetime.now())+"+00:00"

                # Record in Kinesis Firehose
                json_result = {
                    "RuleARN": ConfigRules["ConfigRuleArn"],
                    "RecordedInDDBTimestamp": timestamp_now.split(".")[0].split("+")[0],
                    "RuleName": ConfigRules["ConfigRuleName"],
                    "ResourceType": ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'],
                    "ResourceId": ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'],
                    "LastResultRecordedTime": str(ResultIdentifiers['ResultRecordedTime']).split(".")[0].split("+")[0],
                    "AccountID": invoking_event['awsAccountId']
                    }

                try:
                    if is_compliance_result_whitelisted(json_result):
                        json_result["ComplianceType"] = "COMPLIANT"
                        json_result["WhitelistedComplianceType"] = "True"
                    else:
                        json_result["ComplianceType"] = ResultIdentifiers['ComplianceType']
                        json_result["WhitelistedComplianceType"] = "False"
                except Exception:
                    traceback.print_exc(file=sys.stdout)
                    json_result["ComplianceType"] = ResultIdentifiers['ComplianceType']
                    json_result["WhitelistedComplianceType"] = "Error"

                if 'AccountClassification' in rule_parameters:
                    json_result["AccountClassification"] = rule_parameters["AccountClassification"]

                #if RuleCriticity is in the name
                if ConfigRules["ConfigRuleName"].split("-")[0] in ["1_CRITICAL", "2_HIGH", "3_MEDIUM", "4_LOW"]:
                    json_result["RuleCriticity"] = ConfigRules["ConfigRuleName"].split("-")[0]

                kinesis_client.put_record(
                    DeliveryStreamName='Firehose-Compliance-as-code',
                    Record={
                        'Data': str(json.dumps(json_result) + "\n")
                    }
                )

                if SNS_TOPIC_ARN != "" and ResultIdentifiers['ComplianceType'] == "NON_COMPLIANT":
                    send_results_to_sns(ResultIdentifiers, invoking_event['awsAccountId'], timestamp_now)

            if "NextToken" in rule_compliance_details:
                next_token = rule_compliance_details['NextToken']
                rule_compliance_details = config.get_compliance_details_by_config_rule(ConfigRuleName=ConfigRules["ConfigRuleName"], Limit=100, NextToken=next_token)
            else:
                break

    if CFN_APP_RULESET_STACK_NAME == "" or CFN_APP_RULESET_S3_BUCKET == "" or CFN_APP_RULESET_TEMPLATE_NAME == "":
        config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": "AWS::::Account",
                    "Annotation": "All the parameters (CFN_APP_RULESET_STACK_NAME, CFN_APP_RULESET_S3_BUCKET, CFN_APP_RULESET_TEMPLATE_NAME) must be set in the code of the Rule named Compliance_Validation. Contact the Security team.",
                    "ComplianceResourceId": event['configRuleArn'].split(":")[4],
                    "ComplianceType": "NON_COMPLIANT",
                    "OrderingTimestamp": invoking_event['notificationCreationTime']
                },
            ],
            ResultToken=result_token
        )
    else:
        latest_cfn = validate_if_latest_cfn()
        config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": "AWS::::Account",
                    "Annotation": latest_cfn["Annotation"],
                    "ComplianceResourceId": event['configRuleArn'].split(":")[4],
                    "ComplianceType": latest_cfn["ComplianceType"],
                    "OrderingTimestamp": invoking_event['notificationCreationTime']
                },
            ],
            ResultToken=result_token
            )
