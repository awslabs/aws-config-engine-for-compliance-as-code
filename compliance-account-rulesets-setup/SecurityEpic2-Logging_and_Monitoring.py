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
# Logging and Monitoring
# 2.1 | cloudtrail_centralized_encrypted_lfi
# 2.2 | cloudwatch_event_bus_centralized
# 2.3 | config_enabled_centralized
# 2.4 | guardduty_enabled_centralized
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

## Specify the account ID (12 digits) where Amazon CloudWatch should send all events. Ideally, it should be a centralized security monitoring AWS Account. 
AMAZON_CLOUDWATCH_EVENT_RULE_NAME = 'All_Events_to_Security_Monitoring_Account-DO-NOT-MODIFY'
AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID = ''

## Specify the bucket name where AWS Config should be centralized, ideally in a centralized Logging AWS Account. The bucket can in another region and/or another account.
AWS_CONFIG_S3_BUCKET_NAME = ''

## Specify the account ID (12 digits) where Amazon GuardDuty should send all events. Ideally, it should be a centralized security monitoring AWS Account. 
AMAZON_GUARDDUTY_ACCOUNT_ID = ''

########
# Code #
########

def LM_2_1_cloudtrail_centralized_encrypted_lfi(event, rule_parameters):
    # This rule verifies that a defined CloudTrail Trail send all logs to centralized S3 bucket.
    #
    # Scope
    # This rule covers one particular trail and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following parameters in the Config Rules configuration: 
    # 1) RoleToAssume [present by default] 
    # Configure the following in the code of this lambda function
    # 2) AWS_CLOUDTRAIL_NAME [Name of the Trail to look for]
    # 3) AWS_CLOUDTRAIL_S3_BUCKET_NAME [Name of the S3 bucket, ideally in the centralized Security Logging Account]
    # 4) AWS_CLOUDTRAIL_KMS_KEY_ARN [KMS CMK ARN used to encrypt CloudTrail, ideally in the centralized Security Logging Account]
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
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" do not log ALL Management events."
                }
            elif str(correct_trail_selector['DataResources'][0]) != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
                response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named "+ AWS_CLOUDTRAIL_NAME +" do not log ALL S3 Data Events."
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

def LM_2_2_cloudwatch_event_bus_centralized(event, rule_parameters):
    # This rule verifies that a defined Event Rule sends all events to a centralized Security Monitoring AWS Account.
    #
    # Scope
    # This rule covers all regions in one account from a single region and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following parameters in the Config Rules configuration: 
    # 1) RoleToAssume [present by default] 
    # Configure the following in the code of this lambda function
    # 2) AMAZON_CLOUDWATCH_EVENT_RULE_NAME [Name of the Rule to look for]
    # 3) AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID [Account ID of the centralized Security Monitoring Account, 12-digit]
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
        region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
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
    
    

def LM_2_3_config_enabled_centralized(event, rule_parameters):
    # This rule verifies that AWS Config is enabled and send the configuration snapshots in a central S3 bucket.
    #
    # Scope
    # This rule covers all regions in one account from a single region and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following parameters in the Config Rules configuration: 
    # 1) RoleToAssume [present by default] 
    # Configure the following in the code of this lambda function
    # 2) AWS_CONFIG_S3_BUCKET_NAME [Name of the centralized Bucket, not the ARN]
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
        region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
        configservice = region_session.client("config")
        
        eval['Configuration'] = configservice.describe_delivery_channels()['DeliveryChannels']
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

def LM_2_4_guardduty_enabled_centralized(event, rule_parameters):
    # This rule verifies that Amazon GuardDuty and is centralized in a central AWS Account.
    #
    # Scope
    # This rule covers all regions in one account from a single region and is triggered periodically.
    #
    # Prerequisites 
    # Configure the following parameters in the Config Rules configuration: 
    # 1) RoleToAssume [present by default] 
    # Configure the following in the code of this lambda function
    # 2) AMAZON_GUARDDUTY_ACCOUNT_ID [Account ID of the centralized Security Monitoring Account, 12-digit]
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
        eval={}
        region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
        guard_client = region_session.client("guardduty")

            
        # eval["ComplianceResourceType"]="AWS::GuardDuty::Detector"
        eval["ComplianceResourceType"]="AWS::::Account"
        eval["ComplianceResourceId"]= region['RegionName'] + " " + event['configRuleArn'].split(":")[4]
        
        try:
            eval['DetectorsId'] = guard_client.list_detectors()['DetectorIds']
        except:
            print("Amazon GuardDuty is not available in "+ str(region['RegionName']) +".")
            continue
        
        if len(eval['DetectorsId'])==0:
            response= {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "GuardDuty is not configured in that region."
                }     
        else:      
            detector_info = guard_client.get_detector(DetectorId=eval['DetectorsId'][0])
            eval['Status'] = detector_info['Status']

            if eval['Status'] == "DISABLED":
                response= {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "GuardDuty is not enabled in that region."
                    }
            elif not re.match("^[0-9]{12}$",AMAZON_GUARDDUTY_ACCOUNT_ID):
                response = {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "The parameter \"AMAZON_GUARDDUTY_ACCOUNT_ID\" is not correct in the lambda code. Contact the Security team."
                    }        
            else:
                gd_master = guard_client.get_master_account(DetectorId=eval['DetectorsId'][0])
                print(gd_master)
                gd_invites = guard_client.list_invitations()
                print(gd_invites)
                
                if "Master" not in gd_master and "Invitations" not in gd_invites:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "GuardDuty has no invitation from the Central account. Contact the Security team."
                        }
                elif "Master" not in gd_master and "Invitations" in gd_invites:
                    central_account_invite = False
                    for invite in gd_invites["Invitations"]:
                        if invite["AccountId"] != AMAZON_GUARDDUTY_ACCOUNT_ID:
                            continue
                        else:
                            central_account_invite = True
                    if central_account_invite == False:
                        response = {
                            "ComplianceType": "NON_COMPLIANT",
                            "Annotation": "GuardDuty has no invitation from the Central account. Contact the Security team."
                            }
                    else:
                        response = {
                            "ComplianceType": "NON_COMPLIANT",
                            "Annotation": "GuardDuty has an invitation from the Central account, but it is not accepted. Please accept the invitation."
                            }
                else:
                    if AMAZON_GUARDDUTY_ACCOUNT_ID != gd_master["Master"]["AccountId"]:
                        response = {
                            "ComplianceType": "NON_COMPLIANT",
                            "Annotation": "GuardDuty is centralized in another account (" + str(gd_master["Master"]["AccountId"]) + ") than the account specified as parameter (" + str(AMAZON_GUARDDUTY_ACCOUNT_ID) + ")."
                            }
                    else:
                        if gd_master["Master"]["RelationshipStatus"] != "Monitored":
                            response = {
                                "ComplianceType": "NON_COMPLIANT",
                                "Annotation": "GuardDuty has the correct Central account, but it is not in 'monitoring' state. Contact the Security team."
                                }
                        else:
                            response = {
                                "ComplianceType": "COMPLIANT",
                                "Annotation": "GuardDuty is enabled and centralized in that region."
                                }                        
                        
        eval["ComplianceType"]=response["ComplianceType"]
        eval["Annotation"]=response["Annotation"]
        eval["OrderingTimestamp"]=json.loads(event["invokingEvent"])['notificationCreationTime']
        put_eval(eval, result_token)

def get_sts_session(event, rolename, region_name=False):
    sts = boto3.client("sts")
    RoleArn=str("arn:aws:iam::" + event['configRuleArn'].split(":")[4] + ":role/" + rolename)
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

def put_eval(eval,token):
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

def check_discrete_mode(event):
    try:
        mode = int(event['configRuleName'].split("-")[1].split("_")[2])
        return mode
    except:
        return "All"
        
# This is the handler that is invoked by Lambda
def lambda_handler(event, context):
    global STS_SESSION
    STS_SESSION = ''
    
    global result_token
    if "resultToken" in event:
        result_token = event["resultToken"]
    else:
        result_token = "No token found."

    rule_parameters={}
    if 'ruleParameters' in event:
        if "RoleToAssume" not in event['ruleParameters']:
            return "Error: Missing the parameter named RoleToAssume"
        rule_parameters = json.loads(event['ruleParameters'])
    else:
        return "Error: Missing the parameter named RoleToAssume"
    
    
    STS_SESSION = get_sts_session(event, rule_parameters['RoleToAssume'])

    # Initiate depending if the Rule has been deployed in Discrete mode or not.
    
    DiscreteModeRule = check_discrete_mode(event)
    
    if DiscreteModeRule == 1 or DiscreteModeRule == "All":
        LM_2_1_cloudtrail_centralized_encrypted_lfi(event, rule_parameters)
        
    if DiscreteModeRule == 2 or DiscreteModeRule == "All":
        LM_2_2_cloudwatch_event_bus_centralized(event, rule_parameters)
    
    if DiscreteModeRule == 3 or DiscreteModeRule == "All":  
        LM_2_3_config_enabled_centralized(event, rule_parameters)
    
    if DiscreteModeRule == 4 or DiscreteModeRule == "All":  
        LM_2_4_guardduty_enabled_centralized(event, rule_parameters)