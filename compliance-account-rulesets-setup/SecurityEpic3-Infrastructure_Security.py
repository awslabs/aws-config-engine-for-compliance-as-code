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
# Infrastructure Security
# 3.1 | vpc_securitygroup_default_blocked
# 3.2 | vpc_no_route_to_igw

import json
import boto3
import sys
import time
from datetime import datetime

def IS_3_1_vpc_securitygroup_default_blocked(event, rule_parameters):

    regions = STS_SESSION.client("ec2").describe_regions()['Regions']
    for region in regions:
        region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
        ec2 = region_session.client("ec2")
        security_groups = ec2.describe_security_groups()
        for sg in security_groups['SecurityGroups']: # parsing all because filtering by GroupName returns a ClientError when there are no VPCs in the region
            # print("sg is " + json.dumps(sg))
            if 'VpcId' in sg and sg['GroupName'] == "default":
                eval = {}
                eval["ComplianceResourceType"] = "AWS::EC2::SecurityGroup"
                eval['configuration'] = sg
                eval["ComplianceResourceId"] = "arn:aws:ec2:" + region['RegionName'] + ":" + event['configRuleArn'].split(":")[4] + ":security_group/" + sg['GroupId']
                if  len(eval['configuration']['IpPermissions']):
                    response= {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "There are permissions on the ingress of this security group."
                    }
                elif len(eval['configuration']['IpPermissionsEgress']):
                    response= {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "There are permissions on the egress of this security group."
                    }
                else:
                    response= {
                    "ComplianceType": "COMPLIANT",
                    "Annotation": "This security group has no permission."
                    }
                eval["ComplianceResourceType"] = "AWS::EC2::SecurityGroup"
                eval["ComplianceType"]=response["ComplianceType"]
                eval["Annotation"]=response["Annotation"]
                eval["OrderingTimestamp"]=json.loads(event["invokingEvent"])['notificationCreationTime']
                put_eval(eval, result_token)

def IS_3_2_vpc_main_route_table_no_igw(event, rule_parameters):
    ec2_client = STS_SESSION.client("ec2")
    
    route_tables = ec2_client.describe_route_tables(Filters=[{"Name": "association.main", "Values" : ["true"]}])['RouteTables']
    # print(route_tables)    
    for route_table in route_tables:
        eval = {}
        eval["ComplianceResourceId"] = route_table['VpcId']
        
        igw_route = False
        for route in route_table['Routes']:
            if route['GatewayId'].startswith('igw-'):
                igw_route = True

        if igw_route == False:
            response= {
            "ComplianceType": "COMPLIANT",
            "Annotation": "No IGW route is present in the Main route table of this VPC."
            }
        else:
            response= {
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "An IGW route is present in the Main route table of this VPC (RouteTableId: "+ route_table['RouteTableId'] +")."
            }
                                           
        eval["ComplianceResourceType"] = "AWS::EC2::VPC"
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
        
# This is the handler that's invoked by Lambda
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
        IS_3_1_vpc_securitygroup_default_blocked(event, rule_parameters)
        
    if DiscreteModeRule == 2 or DiscreteModeRule == "All":
        IS_3_2_vpc_main_route_table_no_igw(event, rule_parameters)
        
    
    
