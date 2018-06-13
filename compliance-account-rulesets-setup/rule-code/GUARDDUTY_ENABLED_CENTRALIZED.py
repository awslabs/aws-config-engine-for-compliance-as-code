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
# guardduty_enabled_centralized
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

## Specify the account ID (12 digits) where Amazon GuardDuty should send all events. Ideally, it should be a centralized security monitoring AWS Account. 
AMAZON_GUARDDUTY_ACCOUNT_ID = ''

########
# Code #
########

def guardduty_enabled_centralized(event):
    # This rule verifies that Amazon GuardDuty and is centralized in a central AWS Account.
    #
    # Scope
    # This rule covers all regions in one account from a single region and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following in the code of this lambda function
    # 1) AMAZON_GUARDDUTY_ACCOUNT_ID [Account ID of the centralized Security Monitoring Account, 12-digit]
    #
    # Use cases
    # The following logic is applied for each region: 
    # GuardDuty is not configured -> NOT COMPLIANT
    # GuardDuty is not enabled -> NOT COMPLIANT
    # AMAZON_GUARDDUTY_ACCOUNT_ID is not a 12-digit string -> NOT COMPLIANT
    # GuardDuty is not centralized in AMAZON_GUARDDUTY_ACCOUNT_ID and has no invitation -> NOT COMPLIANT
    # GuardDuty is not centralized in AMAZON_GUARDDUTY_ACCOUNT_ID and has an invitation -> NOT COMPLIANT
    # GuardDuty is centralized but not in AMAZON_GUARDDUTY_ACCOUNT_ID -> NOT COMPLIANT
    # GuardDuty is centralized in AMAZON_GUARDDUTY_ACCOUNT_ID but is not in "Monitoring" state" -> NOT COMPLIANT
    # GuardDuty is enabled and centralized in AMAZON_GUARDDUTY_ACCOUNT_ID -> COMPLIANT

    regions = STS_SESSION.client("ec2").describe_regions()['Regions']

    for region in regions:
        region_session = get_sts_session(event, region['RegionName'])
        guard_client = region_session.client("guardduty")

        if not re.match("^[0-9]{12}$", AMAZON_GUARDDUTY_ACCOUNT_ID):
            put_eval(build_evaluation(event, "NON_COMPLIANT",
                                      "The parameter \"AMAZON_GUARDDUTY_ACCOUNT_ID\" is not correct in the lambda code. Contact the Security team.", region), result_token)

        try:
            detectorIds = []
            detectorIds = guard_client.list_detectors()['DetectorIds']
        except:
            print("Amazon GuardDuty is not available in "+ str(region['RegionName']) +".")
            continue
        
        if len(detectorIds) == 0:
            put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty is not configured.", region), result_token)
            continue
        
        detector = detectorIds[0]

        if not is_detector_enabled(guard_client, detector):
            put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty is not enabled.", region), result_token)
            continue
        
        if not AMAZON_GUARDDUTY_ACCOUNT_ID:
            put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty is enabled, but the parameter AMAZON_GUARDDUTY_ACCOUNT_ID is not configured in the Compliance engine.", region), result_token)
            continue
        
        if AMAZON_GUARDDUTY_ACCOUNT_ID == json.loads(event["invokingEvent"])['awsAccountId']:
            put_eval(build_evaluation(event, "COMPLIANT", "GuardDuty is enabled. This account is the centralized account.", region), result_token)
            continue
        
        gd_master = guard_client.get_master_account(DetectorId=detector)
        
        if "Master" not in gd_master:
            try:
                if is_there_invitation_from_master(guard_client):
                    put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty has an invitation from the Central account, but it is not accepted. Please accept this invitation.", region), result_token)
                    continue
                else:
                    put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty is enabled but not centralized. It has no invitation from the Central account.", region), result_token)
                    continue
            except:
                # Still work if list_invitations() fails
                put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty is enabled but not centralized.", region), result_token)
                continue
        
        if AMAZON_GUARDDUTY_ACCOUNT_ID == gd_master["Master"]["AccountId"]:
            if gd_master["Master"]["RelationshipStatus"] == "Monitored":
                put_eval(build_evaluation(event, "COMPLIANT", "GuardDuty is enabled and centralized.", region), result_token)
                continue
            else:
                put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty has the correct Central account, but it is not in 'Monitored' state.", region), result_token)
                continue
        else: 
            put_eval(build_evaluation(event, "NON_COMPLIANT", "GuardDuty is centralized in another account (" + str(gd_master["Master"]["AccountId"]) + ") than the account specified as parameter (" + str(AMAZON_GUARDDUTY_ACCOUNT_ID) + ").", region), result_token)
            continue

def is_there_invitation_from_master(guard_client):
    gd_invites = guard_client.list_invitations()
    # list_invitations() return an empty array on Invitations. if no invitation
    
    for invite in gd_invites["Invitations"]:
        if invite["AccountId"] != AMAZON_GUARDDUTY_ACCOUNT_ID:
            continue
        else:
            return True
            
    return False
    
def is_detector_enabled(guard_client, detector):
    detector_info = guard_client.get_detector(DetectorId=detector)
    if detector_info['Status'] == "ENABLED":
        return True
    else:
        return False
    
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
    
    guardduty_enabled_centralized(event)