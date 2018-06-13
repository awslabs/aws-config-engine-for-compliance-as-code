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
# config_enabled_centralized


import json
import boto3
import sys
import time
import re
from datetime import datetime

#############################################
# Parameters to modify for your environment #
#############################################

## Specify the bucket name where AWS Config should be centralized, ideally in a centralized Logging AWS Account. The bucket can in another region and/or another account.
AWS_CONFIG_S3_BUCKET_NAME = ''

########
# Code #
########
   
def config_enabled_centralized(event):
    # This rule verifies that AWS Config is enabled and send the configuration snapshots in a central S3 bucket.
    #
    # Scope
    # This rule covers all regions in one account from a single region and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following in the code of this lambda function
    # 1) AWS_CONFIG_S3_BUCKET_NAME [Name of the centralized Bucket, not the ARN]
    #
    # Use cases
    # The following logic is applied for each region: 
    # Config DeliveryChannel or ConfigurationRecorder is not configured -> NOT COMPLIANT
    # Config is not enabled ->  NOT COMPLIANT
    # Config is enabled but does not record all items (all Global resources are not checked) -> NOT COMPLIANT
    # In the region where the rule is, Config is enabled but does not record all resources or all global resources -> NOT COMPLIANT
    # Config is enabled but the parameter "AWS_CONFIG_S3_BUCKET_NAME" is not configured in the Rule configuration -> NOT COMPLIANT
    # Config is enabled, the parameter "AWS_CONFIG_S3_BUCKET_NAME" is configured but the bucket configured in Config does not match -> NOT COMPLIANT
    # Config is enabled, the parameter "AWS_CONFIG_S3_BUCKET_NAME" is configured and the bucket configured in Config matches -> COMPLIANT
    #
    # Annotation are given on each evaluation to assist the application owner.
    
    regions = STS_SESSION.client("ec2").describe_regions()['Regions']
        
    for region in regions:
        eval={}
        region_session = get_sts_session(event, region['RegionName'])
        configservice = region_session.client("config")
                
        try:
            eval['Configuration'] = configservice.describe_delivery_channels()['DeliveryChannels']
        except:
            print("AWS Config is not available in "+ str(region['RegionName']) +".")
            continue
        
        eval['Status'] = configservice.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
        eval['Recorder'] = configservice.describe_configuration_recorders()['ConfigurationRecorders']
        eval['IncludeGlobalResources'] = False
        if region['RegionName'] == event['configRuleArn'].split(":")[3]:
            eval['IncludeGlobalResources'] = True
        
        eval["ComplianceResourceType"]="AWS::Config::ConfigurationRecorder"
        eval["ComplianceResourceId"]="arn:aws:config:" + region['RegionName'] + ":" + event['configRuleArn'].split(":")[4]

        if len(eval['Configuration']) == 0 or len(eval['Status']) == 0:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "Config is not configured in that region."
                }
        elif eval['Status'][0]['recording'] == False:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "Config is not enabled in that region."
                }
        elif eval['Recorder'][0]['recordingGroup']['allSupported'] != True:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "Config is not recording all resources supported in that region."
                }
        elif eval['IncludeGlobalResources'] == True and eval['Recorder'][0]['recordingGroup']['includeGlobalResourceTypes'] != True:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "Config is not recording global resources in that region."
                }
        elif AWS_CONFIG_S3_BUCKET_NAME == '':
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "Config is enabled but no centralized bucket \"AWS_CONFIG_S3_BUCKET_NAME\" is configured in the lambda code. Contact the Security team."
                }
        elif AWS_CONFIG_S3_BUCKET_NAME != eval['Configuration'][0]['s3BucketName']:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "Config is enabled but do not send the configuration snapshots in the correct centralized bucket " + AWS_CONFIG_S3_BUCKET_NAME +"."
                }
        else:
            response= {
                "ComplianceType": "COMPLIANT",
                "Annotation": "Config is enabled and send the configuration snapshots in the centralized bucket " + AWS_CONFIG_S3_BUCKET_NAME +"."
                }
        
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
 
    config_enabled_centralized(event)