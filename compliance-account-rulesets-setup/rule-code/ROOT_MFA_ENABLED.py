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
# Identity and Access Management
# root_mfa_enabled
#

import json
import boto3
import sys
import csv
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
    return(sts_session)

def root_mfa_enabled():
    
    iam = STS_SESSION.client("iam")
        
    response = iam.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] != 1:
        status = 'NON_COMPLIANT'
    else:
        status = 'COMPLIANT'
          
    config = STS_SESSION.client("config")
    config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": "AWS::::Account",
                    "ComplianceResourceId": "Root MFA enabled",
                    "ComplianceType": status,
                    "OrderingTimestamp": str(datetime.now())
                },
            ],
            ResultToken=result_token
        )

# This is the handler that's invoked by Lambda
def lambda_handler(event, context):

    global STS_SESSION
    global result_token
    if "resultToken" in event:
        result_token = event["resultToken"]

    STS_SESSION = get_sts_session(event)
    
    root_mfa_enabled()
