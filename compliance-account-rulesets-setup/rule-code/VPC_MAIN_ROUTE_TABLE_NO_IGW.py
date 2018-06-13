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
# Infrastructure Security
# vpc_main_route_table_no_igw
#

import json
import boto3
import sys
import time
from datetime import datetime

def vpc_main_route_table_no_igw(event):
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
       
# This is the handler that's invoked by Lambda
def lambda_handler(event, context):
    global STS_SESSION
    STS_SESSION = ''
    
    global result_token
    if "resultToken" in event:
        result_token = event["resultToken"]
    else:
        result_token = "No token found."

    STS_SESSION = get_sts_session(event)

    vpc_main_route_table_no_igw(event)
