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

import boto3
import json
import time
from datetime import datetime
import os

# DEFINE SNS TOPIC
SNS_TOPIC_ARN = ''

# DEFINE CLOUDFORMATION S3 LOCATION
# This controls enables the Compliance Validation of the Current deployment by verifying if the latest CFn template is deployed in the Application account. Add the cfn file in a specific bucket in the Compliance Account.
CFN_APP_RULESET_STACK_NAME = ''
CFN_APP_RULESET_S3_BUCKET = ''
CFN_APP_RULESET_TEMPLATE_NAME = ''


def get_sts_session(event, rolename):
    global STS_SESSION
    sts = boto3.client("sts")
    response = sts.assume_role(
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

    s3_client = boto3.client("s3")
    object = s3_client.get_object(Bucket=CFN_APP_RULESET_S3_BUCKET,Key=CFN_APP_RULESET_TEMPLATE_NAME)
    template = object["Body"].read().decode("utf-8")
    
    parameter_list = []
    
    for param in cfn_client.describe_stacks(StackName=CFN_APP_RULESET_STACK_NAME)['Stacks'][0]['Parameters']:
        parameter_list.append(
            {
                'ParameterKey': param['ParameterKey'],
                'UsePreviousValue': True
            })
    
    # Delete old change_set, if necessary
    try:
        print("Verify if existing ChangeSet")
        cfn_client.describe_change_set(ChangeSetName='ComplianceValidation', StackName=CFN_APP_RULESET_STACK_NAME)
        print("Existing ChangeSet, time to delete")
        cfn_client.delete_change_set(ChangeSetName='ComplianceValidation', StackName=CFN_APP_RULESET_STACK_NAME)
        print("Waiting time")
        time.sleep(5)
    except:
        print("No ChangeSet")

    # Create new change_set
    response_create_change = cfn_client.create_change_set(
        StackName=CFN_APP_RULESET_STACK_NAME,
        TemplateBody = template,
        ChangeSetName='ComplianceValidation',
        Capabilities=['CAPABILITY_NAMED_IAM'],
        Parameters=parameter_list
        )
    
    result = {}
    
    while cfn_client.describe_change_set(ChangeSetName=response_create_change["Id"])["Status"] != "CREATE_COMPLETE":
        if cfn_client.describe_change_set(ChangeSetName=response_create_change["Id"])["Status"] == "FAILED":
            result = {
                "Annotation" : "This account runs the latest Compliance-as-code stack.",
                "ComplianceType" : "COMPLIANT"
            }
            return result
        time.sleep(3)

    print("Change set" + str(cfn_client.describe_change_set(ChangeSetName=response_create_change["Id"])))
    
    result = {
            "Annotation" : "This account is not running the latest Compliance-as-code stack. Contact the Security team.",
            "ComplianceType" : "NON_COMPLIANT"
        }
    
    cfn_client.delete_change_set(ChangeSetName=response_create_change["Id"])
    
    return result
    
def lambda_handler(event, context):
        
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event["ruleParameters"])

    # Assume Role to get access to the application account information via sts session named STS_SESSION
    get_sts_session(event, rule_parameters["RoleToAssume"])

    result_token = "No token found."

    if "resultToken" in event:
        result_token = event["resultToken"]

    config = STS_SESSION.client('config')
    dynamodb = boto3.client('dynamodb')
    
    config_all_rules = config.describe_config_rules()
    # print(config_all_rules)

    for ConfigRules in config_all_rules["ConfigRules"]:

        rule_compliance_details = config.get_compliance_details_by_config_rule(ConfigRuleName=ConfigRules["ConfigRuleName"],Limit=100)

        # Skip this rule in the result
        if ConfigRules["ConfigRuleId"]==event['configRuleId']:
            continue        
        
        timestamp_lambda_exec = invoking_event['notificationCreationTime']   
        try:
            timestamp_result_recorded_time = rule_compliance_details['EvaluationResults'][0]['ResultRecordedTime']
        except:
            continue
        
        kinesis_client = boto3.client("firehose")
        
        while True:
            for ResultIdentifiers in rule_compliance_details['EvaluationResults']:
                timestamp_now = str(datetime.now())+"+00:00"
                # print("Now = "+timestamp_now)
                # print("ResourceId: "+ ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'])
                
                # Record in Kinesis Firehose
                json_result = {
                    "RuleARN": ConfigRules["ConfigRuleArn"],
                    "RecordedInDDBTimestamp": timestamp_now.split(".")[0].split("+")[0],
                    "RuleName": ConfigRules["ConfigRuleName"],
                    "ResourceType": ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'],
                    "ResourceId": ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'],
                    "ComplianceType": ResultIdentifiers['ComplianceType'],
                    "LastResultRecordedTime": str(ResultIdentifiers['ResultRecordedTime']).split(".")[0].split("+")[0],
                    "AccountID": invoking_event['awsAccountId']
                    }
        
                if 'AccountClassification' in rule_parameters: 
                    json_result["AccountClassification"] = rule_parameters["AccountClassification"]
                    
                #if RuleCriticity is in the name
                if ConfigRules["ConfigRuleName"].split("-")[0] in ["1_CRITICAL", "2_HIGH", "3_MEDIUM", "4_LOW"]:
                    json_result["RuleCriticity"] = ConfigRules["ConfigRuleName"].split("-")[0]
                        
                response = kinesis_client.put_record(
                    DeliveryStreamName='Firehose-Compliance-as-code',
                    Record={
                        'Data': str(json.dumps(json_result) + "\n")
                    }
                )
                
                # print(SNS_TOPIC_ARN)
                # print(ResultIdentifiers['ComplianceType'])
                
                if SNS_TOPIC_ARN != "" and ResultIdentifiers['ComplianceType']=="NON_COMPLIANT":
                    send_results_to_sns(ResultIdentifiers, invoking_event['awsAccountId'], timestamp_now)
      
            if "NextToken" in rule_compliance_details:
                next_token = rule_compliance_details['NextToken']
                rule_compliance_details = config.get_compliance_details_by_config_rule(ConfigRuleName=ConfigRules["ConfigRuleName"],Limit=100, NextToken=next_token)
            else:
                break
                    
        
    if CFN_APP_RULESET_STACK_NAME == "" or CFN_APP_RULESET_S3_BUCKET == "" or CFN_APP_RULESET_TEMPLATE_NAME == "":
        config.put_evaluations(
                Evaluations=[
                    {
                        "ComplianceResourceType": "AWS::::Account",
                        "Annotation": "All the parameters (CFN_APP_RULESET_STACK_NAME, CFN_APP_RULESET_S3_BUCKET, CFN_APP_RULESET_TEMPLATE_NAME) must be set in the code of the Rule named Compliance_Validation. Contact the Security team.",
                        "ComplianceResourceId": "Compliance-as-code CloudFormation",
                        "ComplianceType": "NON_COMPLIANT",
                        "OrderingTimestamp": timestamp_result_recorded_time
                    },
                ],
                ResultToken=result_token
            )
    else:
        latest_cfn = validate_if_latest_cfn()
        config.put_evaluations(
                Evaluations=[
                    {
                        "ComplianceResourceType": "AWS::CloudFormation::Stack",
                        "Annotation": latest_cfn["Annotation"],
                        "ComplianceResourceId": CFN_APP_RULESET_TEMPLATE_NAME,
                        "ComplianceType": latest_cfn["ComplianceType"],
                        "OrderingTimestamp": timestamp_result_recorded_time
                    },
                ],
                ResultToken=result_token
            )