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

#
# Detective Controls
# cloudwatch_event_bus_centralized
#

import json
import boto3
import sys
import time
import re
from datetime import datetime

#############################################
# Parameters to modify for your environment #
#############################################

## Specify the account ID (12 digits) where Amazon CloudWatch should send all events. Ideally, it should be a centralized security monitoring AWS Account. 
AMAZON_CLOUDWATCH_EVENT_RULE_NAME = 'All_Events_to_Security_Monitoring_Account-DO-NOT-MODIFY'
AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID = ''

########
# Code #
########

def cloudwatch_event_bus_centralized(event):
    # This rule verifies that a defined Event Rule sends all events to a centralized Security Monitoring AWS Account.
    #
    # Scope
    # This rule covers all regions in one account from a single region and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following in the code of this lambda function
    # 1) AMAZON_CLOUDWATCH_EVENT_RULE_NAME [Name of the Rule to look for]
    # 2) AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID [Account ID of the centralized Security Monitoring Account, 12-digit]
    #
    # Use cases
    # The following logic is applied for each region: 
    # No Event Rule is configured -> NOT COMPLIANT
    # No Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value is configured -> NOT COMPLIANT
    # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value is inactive -> NOT COMPLIANT
    # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value does not match the pattern "Send all events" -> NOT COMPLIANT
    # AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID is not a 12-digit string -> NOT COMPLIANT
    # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value has not exactly 1 target -> NOT COMPLIANT
    # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value has not for target the AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID default event bus -> NOT COMPLIANT
    # AMAZON_CLOUDWATCH_EVENT_RULE_NAME Event Rule is matching the pattern "Send all events" and send to AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID and is active -> COMPLIANT

    regions = STS_SESSION.client("ec2").describe_regions()['Regions']
        
    for region in regions:
        eval={}
        region_session = get_sts_session(event, region['RegionName'])
        events_client = region_session.client("events")
        
        eval['Configuration'] = events_client.list_rules()['Rules']
       
        if len(eval['Configuration']) == 0:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "No Event Rule is configured in that region."
                }
        else:
            rule_found = False

            for rule in eval['Configuration']:
                if rule["Name"] == AMAZON_CLOUDWATCH_EVENT_RULE_NAME:
                    rule_found = True
            if rule_found == False:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "No Event Rule named "+ AMAZON_CLOUDWATCH_EVENT_RULE_NAME +" is configured in that region."
                }
            else:
                correct_rule = events_client.describe_rule(Name=AMAZON_CLOUDWATCH_EVENT_RULE_NAME)
                if correct_rule["State"] != 'ENABLED':
                    response= {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "The Event Rule named "+ AMAZON_CLOUDWATCH_EVENT_RULE_NAME +" is not enabled in that region."
                    }               
                elif correct_rule['EventPattern'] != '{"account":["'+correct_rule['Arn'].split(":")[4]+'"]}':
                    response= {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "The Event Rule named "+ AMAZON_CLOUDWATCH_EVENT_RULE_NAME +" does not send all events (see EventPattern in that region."
                    } 
                elif not re.match("^[0-9]{12}$",AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID):
                    response = {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "The parameter \"AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID\" is not correct in the lambda code. Contact the Security team."
                    }
                else:
                    target=events_client.list_targets_by_rule(Rule=AMAZON_CLOUDWATCH_EVENT_RULE_NAME)["Targets"]
                    if len(target)!=1:
                        response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Event Rule named "+ AMAZON_CLOUDWATCH_EVENT_RULE_NAME +" have no or too many targets."
                        }
                    elif target[0]["Arn"] != "arn:aws:events:"+region['RegionName']+":"+AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID+":event-bus/default":
                        response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The target of the Event Rule named "+ AMAZON_CLOUDWATCH_EVENT_RULE_NAME +" is not the Event Bus of "+AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID+"."
                        }
                    else: 
                        response = {
                        "ComplianceType": "COMPLIANT",
                        "Annotation": "The Event Rule named "+ AMAZON_CLOUDWATCH_EVENT_RULE_NAME +" is active and well defined to send all events to "+AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID+" via Event Bus."
                        }

        eval["ComplianceResourceType"]="AWS::::Account"
        eval["ComplianceResourceId"]="CloudWatch Events Rule " + region['RegionName']
        eval["ComplianceType"]=response["ComplianceType"]
        eval["Annotation"]=response["Annotation"]
        eval["OrderingTimestamp"]=json.loads(event["invokingEvent"])['notificationCreationTime']
        put_eval(eval, result_token)
    
def build_evaluation(event, complianceType, annotation, region, eval_resource_type = "AWS::::Account"):
    return {
        "ComplianceResourceType": eval_resource_type,
        "ComplianceResourceId": region['RegionName'] + " " + event['accountId'],
        "ComplianceType": complianceType,
        "Annotation": annotation,
        "OrderingTimestamp": str(json.loads(event["invokingEvent"])['notificationCreationTime'])
    }

def get_sts_session(event, region_name=False):
    sts = boto3.client("sts")
    RoleArn = event["executionRoleArn"]
    if not region_name:
        region_name = event['configRuleArn'].split(":")[3]
    response = sts.assume_role(
        RoleArn=RoleArn,
        RoleSessionName='ComplianceAudit',
        DurationSeconds=900)
    sts_session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
        region_name=region_name,
        botocore_session=None,
        profile_name=None)
    return(sts_session)

def put_eval(eval, token):
    config = STS_SESSION.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": eval["ComplianceResourceType"],
                "ComplianceResourceId": eval["ComplianceResourceId"],
                "ComplianceType": eval["ComplianceType"],
                "Annotation": eval["Annotation"],
                "OrderingTimestamp": eval["OrderingTimestamp"]
            },
        ],
        ResultToken=token
    )
      
# This is the handler that is invoked by Lambda
def lambda_handler(event, context):
    global STS_SESSION
    STS_SESSION = ''
    
    global result_token
    if "resultToken" in event:
        result_token = event["resultToken"]
    else:
        result_token = "No token found."

    STS_SESSION = get_sts_session(event)
 
    cloudwatch_event_bus_centralized(event)
