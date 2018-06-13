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
# This Rule is part of the Security Epics RuleSet. This RuleSet provides guidance on the Security Epics of the AWS Cloud Adoption Framework (CAF)
#
# Identity and Access Management
# iam_policy_no_full_star
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

def iam_policy_no_full_star():    
    iam = STS_SESSION.client("iam")
    response = iam.list_policies(Scope='Local')

    for configuration_item in response["Policies"]:
        policy_info = iam.get_policy(PolicyArn=configuration_item["Arn"])
        print(policy_info)
        if policy_info["Policy"]["IsAttachable"]==False:
            status = "NOT_APPLICABLE"
        else:
            policy_version = iam.get_policy_version(PolicyArn=configuration_item["Arn"], VersionId=policy_info['Policy']['DefaultVersionId'])
            for statement in policy_version['PolicyVersion']['Document']['Statement']:

                star_statement = False
                if type(statement['Action']) is list:
                    for action in statement['Action']:
                        if action == "*":
                            star_statement = True
                else: # just one Action
                    if statement['Action'] == "*":
                        star_statement = True

                star_resource = False
                if type(statement['Resource']) is list:
                    for action in statement['Resource']:
                        if action == "*":
                            star_resource = True
                else: # just one Resource
                    if statement['Resource'] == "*":
                        star_resource = True

                if star_statement and star_resource:
                    status = 'NON_COMPLIANT'
                else:
                    status = 'COMPLIANT'
        
        ResourceId = configuration_item["PolicyId"]
        ResourceType = "AWS::IAM::Policy"
        config = STS_SESSION.client("config")
        config.put_evaluations(
                Evaluations=[
                    {
                        "ComplianceResourceType": ResourceType,
                        "ComplianceResourceId": ResourceId,
                        "ComplianceType": status,
                        "Annotation": "No full * (aka full permission) in an IAM Policy should be attached to IAM Users/Groups/Roles.",
                        "OrderingTimestamp": str(datetime.now())
                    },
                ],
                ResultToken=result_token
            )
    
    # Verify the AWS managed policy named AdminstratorAccess
    admin_response = iam.get_policy(PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ResourceType = "AWS::IAM::ManagedPolicy"
    ResourceId = "AdministratorAccess"
    if int(admin_response["Policy"]["AttachmentCount"])>0:
        status = "NON_COMPLIANT"
    else:
        status = "COMPLIANT"
        
    config = STS_SESSION.client("config")
    config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": ResourceType,
                    "ComplianceResourceId": ResourceId,
                    "ComplianceType": status,
                    "Annotation": "No full * (aka full permission) in an IAM Policy should be attached to IAM Users/Groups/Roles.",
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

    iam_policy_no_full_star()
    
