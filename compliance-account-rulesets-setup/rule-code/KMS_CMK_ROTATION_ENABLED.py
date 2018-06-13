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
# Data Protection
# kms_cmk_rotation_enabled
#

import json
import boto3
import sys
import time
from datetime import datetime

STS_SESSION = ''

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
    return sts_session

def kms_cmk_rotation_enabled(event):
    configuration_item = {}

    regions = STS_SESSION.client("ec2").describe_regions()['Regions']
    for region in regions:
        region_session = get_sts_session(event, region['RegionName'])
        kms_client = region_session.client('kms')
        keys = kms_client.list_keys()
        if len(keys['Keys']) == 0:
            continue
        else:
            for key in keys['Keys']:
                eval = {}
                eval["ComplianceResourceType"] = "AWS::KMS::Key"
                eval["ComplianceResourceId"] = key['KeyArn']
                if kms_client.describe_key(KeyId=key['KeyId'])["KeyMetadata"]["KeyManager"] == "AWS":
                    continue
                if kms_client.get_key_rotation_status(KeyId=key['KeyId'])['KeyRotationEnabled'] == True:
                    response = {
                        "ComplianceType": "COMPLIANT",
                        "Annotation": "The yearly rotation is activated for this key."
                        }
                else:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The yearly rotation is not activated for this key."
                        }
                eval["ComplianceType"]=response["ComplianceType"]
                eval["Annotation"]=response["Annotation"]
                eval["OrderingTimestamp"]=json.loads(event["invokingEvent"])['notificationCreationTime']
                put_eval(eval, result_token)    

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
        
# This is the handler that's invoked by Lambda
def lambda_handler(event, context):
    global STS_SESSION
    global result_token
    if "resultToken" in event:
        result_token = event["resultToken"]

    rule_parameters={}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    STS_SESSION = get_sts_session(event)
    
    kms_cmk_rotation_enabled(event)
