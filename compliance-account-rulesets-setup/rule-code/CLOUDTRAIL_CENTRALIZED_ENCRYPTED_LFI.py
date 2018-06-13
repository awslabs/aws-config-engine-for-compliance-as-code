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
# cloudtrail_centralized_encrypted_lfi
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

## Specify the bucket name where at least 1 AWS CloudTrail should be centralized, ideally in a centralized Logging AWS Account. 
AWS_CLOUDTRAIL_NAME = 'Security_Trail_DO-NOT-MODIFY'
AWS_CLOUDTRAIL_S3_BUCKET_NAME = ''
AWS_CLOUDTRAIL_KMS_KEY_ARN = ''

########
# Code #
########

def cloudtrail_centralized_encrypted_lfi(event):
    # This rule verifies that a defined CloudTrail Trail send all logs to centralized S3 bucket.
    #
    # Scope
    # This rule covers one particular trail and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following in the code of this lambda function
    # 1) AWS_CLOUDTRAIL_NAME [Name of the Trail to look for]
    # 2) AWS_CLOUDTRAIL_S3_BUCKET_NAME [Name of the S3 bucket, ideally in the centralized Security Logging Account]
    # 3) AWS_CLOUDTRAIL_KMS_KEY_ARN [KMS CMK ARN used to encrypt CloudTrail, ideally in the centralized Security Logging Account]
    #
    # Use cases
    # The following logic is applied: 
    # No Trail is configured -> NOT COMPLIANT
    # No Trail named AWS_CLOUDTRAIL_NAME value is configured -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is inactive -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not including global resources -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not multi-region -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value has no Log File Integrity -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not logging all Management Events -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not logging all S3 Data Events -> NOT COMPLIANT
    # AWS_CLOUDTRAIL_S3_BUCKET_NAME is not defined -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not logging in AWS_CLOUDTRAIL_S3_BUCKET_NAME -> NOT COMPLIANT
    # AWS_CLOUDTRAIL_KMS_KEY_ARN is not defined -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not encrypted -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is not encrypted using AWS_CLOUDTRAIL_KMS_KEY_ARN -> NOT COMPLIANT
    # The Trail named AWS_CLOUDTRAIL_NAME value is active, global, log file integrity, logging in AWS_CLOUDTRAIL_S3_BUCKET_NAME and encrypted with AWS_CLOUDTRAIL_KMS_KEY_ARN -> COMPLIANT

    cloudtrail_client = STS_SESSION.client("cloudtrail") 
    
    eval = {}
    eval["Configuration"] = cloudtrail_client.describe_trails()['trailList']
    print(eval)

    if len(eval['Configuration']) == 0:
            response= {
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "No Trail is configured."
            }
    else:
        trail_found = False

        for trail in eval['Configuration']:
            if trail["Name"] == AWS_CLOUDTRAIL_NAME:
                trail_found = True
        if trail_found == False:
            response= {
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "No Trail named "+ AWS_CLOUDTRAIL_NAME +" is configured."
            }
        else:
            correct_trail_status = cloudtrail_client.get_trail_status(Name=AWS_CLOUDTRAIL_NAME)
            correct_trail = cloudtrail_client.describe_trails(trailNameList=[AWS_CLOUDTRAIL_NAME])['trailList'][0]
            correct_trail_selector = cloudtrail_client.get_event_selectors(TrailName=AWS_CLOUDTRAIL_NAME)['EventSelectors'][0]
            print(correct_trail_selector)
            
            if correct_trail_status['IsLogging'] != True:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not enabled."
                }
            if 'LatestDeliveryError' in correct_trail_status:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" did not delivered the log as expected. The current error is " + correct_trail_status['LatestDeliveryError'] + ". Contact the Security team."
                }
            elif correct_trail['IncludeGlobalServiceEvents'] != True:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not logging global resources."
                }
            elif correct_trail['IsMultiRegionTrail'] != True:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not logging in all regions."
                }
            elif correct_trail['LogFileValidationEnabled'] != True:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" has not log file integrity enabled."
                }
            elif correct_trail_selector['ReadWriteType'] != 'All' or correct_trail_selector['IncludeManagementEvents'] != True:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" does not log ALL Management events."
                }
            elif len(correct_trail_selector['DataResources'])==0 or str(correct_trail_selector['DataResources'][0]) != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" does not log ALL S3 Data Events."
                }
            elif AWS_CLOUDTRAIL_S3_BUCKET_NAME == "":
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The parameter \"AWS_CLOUDTRAIL_S3_BUCKET_NAME\" is not defined in the lambda code. Contact the Security team."
                }            
            elif correct_trail['S3BucketName'] != AWS_CLOUDTRAIL_S3_BUCKET_NAME:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not logging in the S3 bucket named " + AWS_CLOUDTRAIL_S3_BUCKET_NAME + "."
                }
            elif AWS_CLOUDTRAIL_KMS_KEY_ARN == "":
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The parameter \"AWS_CLOUDTRAIL_KMS_KEY_ARN\" is not defined in the lambda code. Contact the Security team."
                }
            elif 'KmsKeyId' not in correct_trail:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not encrypted."
                }  
            elif correct_trail['KmsKeyId'] != AWS_CLOUDTRAIL_KMS_KEY_ARN:
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not encrypted using " + AWS_CLOUDTRAIL_KMS_KEY_ARN + "."
                }
            else:
                response = {
                    "ComplianceType": "COMPLIANT",
                    "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is active and well defined to send logs to "+AWS_CLOUDTRAIL_S3_BUCKET_NAME+" and proper encryption."
                    }
    
    eval["ComplianceResourceType"]="AWS::CloudTrail::Trail"
    eval["ComplianceResourceId"]=AWS_CLOUDTRAIL_NAME
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
    
    cloudtrail_centralized_encrypted_lfi(event)