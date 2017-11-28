#
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
from datetime import datetime
import os

# DEFINE SNS TOPIC
SNS_TOPIC_ARN= ""

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
    print(config_all_rules)

    for ConfigRules in config_all_rules["ConfigRules"]:

        rule_compliance_details = config.get_compliance_details_by_config_rule(ConfigRuleName=ConfigRules["ConfigRuleName"])
        rule_compliance_summary = config.describe_compliance_by_config_rule(ConfigRuleNames=[ConfigRules["ConfigRuleName"]])

        if ConfigRules["ConfigRuleId"]==event['configRuleId']: 
            print(rule_compliance_details)
            continue        
        
        #print(rule_compliance_summary)
        #print(rule_compliance_details)
        
        timestamp_lambda_exec = invoking_event['notificationCreationTime']   
        try:
            timestamp_result_recorded_time = rule_compliance_details['EvaluationResults'][0]['ResultRecordedTime']
        except:
            continue
        
        for ResultIdentifiers in rule_compliance_details['EvaluationResults']:
            timestamp_now = str(datetime.now())+"+00:00"
            print("Now = "+timestamp_now)
            print("ResourceId: "+ ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'])
            
            # Update the DynamoDB Events
            UpdateExpressionValue = "set RuleName =:n, ResourceType =:rt, ResourceID =:rid, ComplianceType =:c, LastResultRecordedTime =:lrrt, AccountID =:a"
                        
            ExpressionAttribute = {}
            ExpressionAttribute = {
                    ':n': {'S':ConfigRules["ConfigRuleName"]},
                    ':rt': {'S':ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']},
                    ':rid': {'S':ResultIdentifiers['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']},
                    ':c': {'S':ResultIdentifiers['ComplianceType']},
                    ':lrrt': {'S':str(ResultIdentifiers['ResultRecordedTime'])},
                    ':a': {'S':invoking_event['awsAccountId']}
                    }
            
            if 'AccountClassification' in rule_parameters: 
                UpdateExpressionValue = UpdateExpressionValue +", AccountClassification=:cl"
                ExpressionAttribute[':cl'] = {
                'S': rule_parameters["AccountClassification"]
                }
            
            #if RuleCriticality is in the name
            if ConfigRules["ConfigRuleName"].split("-")[0] in ["1_CRITICAL", "2_HIGH", "3_MEDIUM", "4_LOW"]:
                UpdateExpressionValue = UpdateExpressionValue +", RuleCriticality=:rc"
                ExpressionAttribute[':rc'] = {
                'S': ConfigRules["ConfigRuleName"].split("-")[0]
                }
            responseDDB=dynamodb.update_item(
                TableName='ComplianceEventsTable', 
                Key={
                    'RuleARN':{'S':ConfigRules["ConfigRuleArn"]},
                    'RecordedInDDBTimestamp':{'S':timestamp_now}
                    },
                UpdateExpression=UpdateExpressionValue,
                ExpressionAttributeValues=ExpressionAttribute
                )
            
            #print(SNS_TOPIC_ARN)
            print(ResultIdentifiers['ComplianceType'])
            if SNS_TOPIC_ARN != "" and ResultIdentifiers['ComplianceType']=="NON_COMPLIANT":
                send_results_to_sns(ResultIdentifiers, invoking_event['awsAccountId'], timestamp_now)
        
        # Update the DynamoDB Status
        UpdateExpressionValue = "set RecordedInDDBTimestamp =:t, LastResultRecordedTime = :lrrt, AccountID = :a, RuleName =:n, ComplianceType =:c"
                        
        ExpressionAttribute = {}
        ExpressionAttribute = {
                ':t': {'S':timestamp_now},
                ':lrrt': {'S':str(timestamp_result_recorded_time)},
                ':a': {'S':invoking_event['awsAccountId']},
                ':n': {'S':ConfigRules["ConfigRuleName"]},
                ':c': {'S':rule_compliance_summary["ComplianceByConfigRules"][0]["Compliance"]["ComplianceType"]}
                }
        
        if 'AccountClassification' in rule_parameters: 
            UpdateExpressionValue = UpdateExpressionValue +", AccountClassification=:cl"
            ExpressionAttribute[':cl'] = {
            'S': rule_parameters["AccountClassification"]
            }
        if 'InputParameters' in ConfigRules: 
            if 'RuleCriticality' in json.loads(ConfigRules['InputParameters']):
                UpdateExpressionValue = UpdateExpressionValue +", RuleCriticality=:rc"
                ExpressionAttribute[':rc'] = {
                'S': json.loads(ConfigRules['InputParameters'])["RuleCriticality"]
                }
                    
        dynamodb.update_item(
            TableName='ComplianceStatusTable', 
            Key={
                'RuleARN':{'S':ConfigRules["ConfigRuleArn"]}
                },
            UpdateExpression=UpdateExpressionValue,
            ExpressionAttributeValues=ExpressionAttribute
            )
        
        config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": "AWS::Config::ConfigRule",
                    "Annotation": "This is an annotation for " + ConfigRules["ConfigRuleName"],
                    "ComplianceResourceId": ConfigRules["ConfigRuleName"],
                    "ComplianceType": rule_compliance_summary['ComplianceByConfigRules'][0]['Compliance']['ComplianceType'],
                    "OrderingTimestamp": timestamp_result_recorded_time
                },
            ],
            ResultToken=result_token
        )