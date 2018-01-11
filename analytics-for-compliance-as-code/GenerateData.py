#
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import boto3
import csv
import os
import json
import copy
import random
from datetime import datetime, timezone, tzinfo, timedelta
import string

global RULES_INIT
    
RULES_INIT = {
        'Account': {
            'NumberOfSensitive': 2,
            'NumberOfConfidential': 1,
            'NumberOfPrivate': 2,
            'NumberOfPublic': 1
            },
        'Rules': [        
            {
            'RuleName': 'IAM_1_1_root_no_access',
            'ToNonCompliance': 0.02,
            'ToCompliance': 0.6,
            'RuleCriticity': '1_CRITICAL',
            'ResourceGroup': 'Group2'
            },{
            'RuleName': 'IAM_1_2_root_mfa_enabled',
            'ToNonCompliance': 0.02,
            'ToCompliance': 0.6,
            'RuleCriticity': '1_CRITICAL',
            'ResourceGroup': 'Group2'
            },{
            'RuleName': 'IAM_1_3_root_no_access_key',
            'ToNonCompliance': 0.02,
            'ToCompliance': 0.6,
            'RuleCriticity': '1_CRITICAL',
            'ResourceGroup': 'Group2'
            },{
            'RuleName': 'IAM_1_4_iam_policy_no_full_star',
            'ToNonCompliance': 0.05,
            'ToCompliance': 0.4,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group6'
            },
            {
            'RuleName': 'LM_2_1_cloudtrail_centralized_encrypted_lfi',
            'ToNonCompliance': 0.05,
            'ToCompliance': 0.4,
            'RuleCriticity': '1_CRITICAL',
            'ResourceGroup': 'Group5'
            },
            {
            'RuleName': 'LM_2_2_cloudwatch_event_bus_centralized',
            'ToNonCompliance': 0.02,
            'ToCompliance': 0.6,
            'RuleCriticity': '1_CRITICAL',
            'ResourceGroup': 'Group2'
            },
            {
            'RuleName': 'LM_2_3_config_enabled_centralized',
            'ToNonCompliance': 0.07,
            'ToCompliance': 0.3,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group3'
            },
            {
            'RuleName': 'IS_3_1_vpc_securitygroup_default_blocked',
            'ToNonCompliance': 0.07,
            'ToCompliance': 0.3,
            'RuleCriticity': '3_MEDIUM',
            'ResourceGroup': 'Group7'
            },
            {
            'RuleName': 'IS_3_2_vpc_main_route_table_no_igw',
            'ToNonCompliance': 0.05,
            'ToCompliance': 0.4,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group8'
            },
            {
            'RuleName': 'DP_4_1_kms_cmk_rotation_activated',
            'ToNonCompliance': 0.02,
            'ToCompliance': 0.4,
            'RuleCriticity': '4_LOW',
            'ResourceGroup': 'Group9'
            },
            {
            'RuleName': 'DP_4_2_s3_bucket_public_read_prohibited',
            'ToNonCompliance': 0.05,
            'ToCompliance': 0.4,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group1'
            },
            {
            'RuleName': 'DP_4_3_s3_bucket_public_write_prohibited',
            'ToNonCompliance': 0.07,
            'ToCompliance': 0.5,
            'RuleCriticity': '3_MEDIUM',
            'ResourceGroup': 'Group1'
            },
            {
            'RuleName': 'DP_4_4_s3_bucket_ssl_requests_only',
            'ToNonCompliance': 0.08,
            'ToCompliance': 0.3,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group1'
            },
            {
            'RuleName': 'DP_4_5_ec2_ebs_volume_encrypted',
            'ToNonCompliance': 0.08,
            'ToCompliance': 0.2,
            'RuleCriticity': '3_MEDIUM',
            'ResourceGroup': 'Group10'
            },
            {
            'RuleName': 'DP_4_6_rds_storage_encrypted',
            'ToNonCompliance': 0.05,
            'ToCompliance': 0.2,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group10'
            },
            {
            'RuleName': 'R_6_1_rds_multi_az_enabled',
            'ToNonCompliance': 0.05,
            'ToCompliance': 0.5,
            'RuleCriticity': '2_HIGH',
            'ResourceGroup': 'Group11'
            }
        ],
        'Resources': {
            'Group1': {
                        'ResourceType' : 'AWS::S3::Bucket',
                        'MinNumberOfResouces': 3,
                        'MaxNumberOfResouces': 10,
                        'Variation': 2
                    },
            'Group2': {
                        'ResourceType' : 'AWS::::Account',
                        'MinNumberOfResouces': 1,
                        'MaxNumberOfResouces': 1,
                        'Variation': 0
                    },
            'Group3': {
                        'ResourceType' : 'AWS::EC2::Instance',
                        'MinNumberOfResouces': 10,
                        'MaxNumberOfResouces': 50,
                        'Variation': 10
                    },
            'Group4': {
                        'ResourceType' : 'AWS::Config::ConfigurationRecorder',
                        'MinNumberOfResouces': 2,
                        'MaxNumberOfResouces': 5,
                        'Variation': 0
                    },
            'Group5': {
                        'ResourceType' : 'AWS::CloudTrail::Trail',
                        'MinNumberOfResouces': 1,
                        'MaxNumberOfResouces': 1,
                        'Variation': 0
                    },
            'Group6': {
                        'ResourceType' : 'AWS::IAM::Policy',
                        'MinNumberOfResouces': 5,
                        'MaxNumberOfResouces': 10,
                        'Variation': 1
                    },
            'Group7': {
                        'ResourceType' : 'AWS::EC2::SecurityGroup',
                        'MinNumberOfResouces': 7,
                        'MaxNumberOfResouces': 15,
                        'Variation': 2
                    },
            'Group8': {
                        'ResourceType' : 'AWS::EC2::VPC',
                        'MinNumberOfResouces': 1,
                        'MaxNumberOfResouces': 3,
                        'Variation': 1
                    },
            'Group9': {
                        'ResourceType' : 'AWS::KMS::Key',
                        'MinNumberOfResouces': 5,
                        'MaxNumberOfResouces': 8,
                        'Variation': 1
                    },
            'Group10': {
                        'ResourceType' : 'AWS::EC2::Volume',
                        'MinNumberOfResouces': 10,
                        'MaxNumberOfResouces': 50,
                        'Variation': 10
                    },
            'Group11': {
                        'ResourceType' : 'AWS::RDS::DBInstance',
                        'MinNumberOfResouces': 6,
                        'MaxNumberOfResouces': 8,
                        'Variation': 2
                    }                             
            }
    }
    
def generate_random_account():
    RandomAccount = str(int(random.random() * 1000000000000))
    while len(RandomAccount)<12:
        RandomAccount = '0'+RandomAccount
    return RandomAccount
    
def generate_account_by_sensitivy():
    response = []
    for x in range(0,RULES_INIT['Account']['NumberOfSensitive']):
        dict = {
            'AccountID': generate_random_account(),
            'AccountClassification': '1_Sensitive'
        }
        response.append(dict.copy())
    for x in range(0,RULES_INIT['Account']['NumberOfConfidential']):
        dict = {
            'AccountID': generate_random_account(),
            'AccountClassification': '2_Confidential'
        }
        response.append(dict.copy())
    for x in range(0,RULES_INIT['Account']['NumberOfPrivate']):
        dict = {
            'AccountID': generate_random_account(),
            'AccountClassification': '3_Private'
        }
        response.append(dict.copy())
    for x in range(0,RULES_INIT['Account']['NumberOfPublic']):
        dict = {
            'AccountID': generate_random_account(),
            'AccountClassification': '4_Public'
        }
        response.append(dict.copy())
    return response

def generate_resource(type, accountID, region="eu-west-1"):
    if type=="AWS::S3::Bucket":
        name = random.choice(['404','age','back','bandwidth','biobreak','brain','cached','cookies','cryptic','deep','defrag','delete','down','eye','Film','huge','interface','just','legacy','meatspace','morph','multitasking','navigate','opt','PDFing','photoshopped','PING','plugged','radar','rant','robot','scaleable','shelfware','showstopper','surf','thread','TMI','unplugged','user','yoyo'])
        name2 = random.choice(['404','age','back','bandwidth','biobreak','brain','cached','cookies','cryptic','deep','defrag','delete','down','eye','Film','huge','interface','just','legacy','meatspace','morph','multitasking','navigate','opt','PDFing','photoshopped','PING','plugged','radar','rant','robot','scaleable','shelfware','showstopper','surf','thread','TMI','unplugged','user','yoyo'])
        ResourceID = "arn:aws:s3:::" + "mycompany-" + name + "-" + name2 + "-" + accountID
    elif type=="AWS::::Account":
        ResourceID = accountID
    elif type=="AWS::Config::ConfigRule":
        id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        ResourceID = "arn:aws:config:"+region+":"+accountID+":config-rule/config-rule-"+id
    elif type=="AWS::EC2::SecurityGroup":
        id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        ResourceID = "arn:aws:ec2:"+region+":"+accountID+":security-group/sg-"+id
    elif type=="AWS::EC2::Instance":
        id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        ResourceID = "arn:aws:ec2:"+region+":"+accountID+":instance/i-"+id
    elif type=="AWS::EC2::Volume":
        id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        ResourceID = "arn:aws:ec2:"+region+":"+accountID+":volume/vol-"+id
    elif type=="AWS::EC2::VPC":
        id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        ResourceID = "arn:aws:ec2:"+region+":"+accountID+":vpc/vpc-"+id 
    elif type=="AWS::Config::ConfigurationRecorder":
        id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        ResourceID = "arn:aws:config:"+region+":"+accountID+":recorder-"+id 
    elif type=="AWS::KMS::Key":
        name = random.choice(['security','application','audit','compliance','app'])  
        name2 = random.choice(['central','dedicated','unique','decentralized', 'confidential', 's3', 'ebs'])          
        ResourceID = "arn:aws:kms:"+region+":"+accountID+":alias/" + name + "-" + name2 
    elif type=="AWS::CloudTrail::Trail":
        name = random.choice(['security','application','audit','compliance','app'])  
        name2 = random.choice(['central','dedicated','unique','decentralized'])          
        ResourceID = "arn:aws:cloudtrail:"+region+":"+accountID+":trail/" + name + "-" + name2 + "-" + accountID 
    elif type=="AWS::IAM::Policy":
        name = random.choice(['ec2','cognito','config','codepipeline','directconnect','dynamodb','ecs','s3','iam'])  
        name2 = random.choice(['admin','poweruser','readonly','ops']) 
        ResourceID = "arn:aws:iam::"+accountID+":policy/" + name + "-" + name2 + "-" + accountID 
    elif type=="AWS::RDS::DBInstance":
        name = random.choice(['app','user','identity','configuration'])  
        name2 = random.choice(['1','prod','test','stage']) 
        ResourceID = "arn:aws:rds::"+accountID+":db/" + name + "-" + name2
    
    return ResourceID

    
    
def generate_data_set():
    rules = []

    account_list = []
    account_list = generate_account_by_sensitivy()    
    rules = []
    
    for account in account_list:
        group_of_resource = {}
        
        for y in range(0, len(RULES_INIT['Resources'])):
            group = RULES_INIT['Resources']['Group'+str(y+1)]
            group_of_resource['Group'+str(y+1)]=[]
            number_of_resources = random.randint(group['MinNumberOfResouces'],group['MaxNumberOfResouces'])
            for x in range(0,number_of_resources):
                group_of_resource['Group'+str(y+1)].append(generate_resource(group['ResourceType'], account["AccountID"]))
    
        for rule in RULES_INIT["Rules"]:
            data_set_entry = {}
            data_set_entry['RuleARN']=generate_resource("AWS::Config::ConfigRule", account["AccountID"])
            data_set_entry['RuleName']=rule["RuleName"]
            data_set_entry['AccountID']=account["AccountID"]
            data_set_entry['AccountClassification']=account["AccountClassification"]
            data_set_entry['ResourceGroup']=rule['ResourceGroup']
            data_set_entry['ResourceType']=RULES_INIT['Resources'][rule['ResourceGroup']]['ResourceType']
            data_set_entry['Resources']=group_of_resource[rule['ResourceGroup']]
            data_set_entry['RuleCriticity']=rule["RuleCriticity"]
            data_set_entry["ToNonCompliance"] = rule["ToNonCompliance"]
            data_set_entry["ToCompliance"] = rule["ToCompliance"]
            
            rules.append(data_set_entry.copy())
    
    data_set = {}
    data_set["Rules"] = rules
    return data_set

def generate_time(base, hour_increment):
    delay = float(hour_increment*3600)
    dt = timedelta(seconds=delay)
    then = base + dt
    return then
    
def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")

def push_1_day(basetime, item, day_increment):
    global COUNT
    dynamodb = boto3.client('dynamodb')
    ExpressionAttribute = []        
    for y in range(0, 24):

        t = generate_time(basetime, y+day_increment*24)
        t = json.loads(json.dumps(t, default=datetime_handler))
        timestamp = str(t).split("T")[0]+ " " +str(t).split("T")[1]+"+00:00" 
        COUNT=COUNT+1
        
        dict = {
                    'PutRequest': {
                        'Item': {
                            'RuleARN':{'S':item["RuleARN"]},
                            'RecordedInDDBTimestamp':{'S':timestamp},
                            'RuleName': {'S':item["RuleName"]},
                            'ResourceType': {'S':item["ResourceType"]},
                            'ResourceID': {'S':item["ResourceID"]},
                            'ComplianceType': {'S':item["ComplianceType"][y+day_increment*24]},
                            'LastResultRecordedTime': {'S':timestamp},
                            'AccountID': {'S':item["AccountID"]},
                            'AccountClassification': {'S':item["AccountClassification"]},
                            'RuleCriticity': {'S':item["RuleCriticity"]}
                            }
                        }
                    }
        ExpressionAttribute.append(dict.copy())        
    
    responseDDB=dynamodb.batch_write_item(
        RequestItems={
            'ComplianceEventsTable': ExpressionAttribute
            }
        )
    return "OK"
    
def lambda_handler(event, context):
    global COUNT
    global RULES_INIT
    
    dynamodb = boto3.client('dynamodb')
    lambda_client = boto3.client('lambda')
    s3_client = boto3.client('s3')

    COUNT=0
    
    event = generate_data_set()
    
    expected_count_events = 0
    for rule in event["Rules"]:
        expected_count_events = expected_count_events + len(rule["Resources"])*24
    
    print("More or less Expected number of Events: " + str(expected_count_events))
    
    for rule in event["Rules"]:
        item = {}
        item["RuleARN"]=rule["RuleARN"]
        item["RuleName"]=rule["RuleName"]
        item["RuleCriticity"]=rule["RuleCriticity"]
        item["ResourceType"]=rule["ResourceType"]
        item["AccountID"]=rule["AccountID"]
        item["AccountClassification"]=rule["AccountClassification"]
        final_compliance = "COMPLIANT"
        
        min_nb_or_resources = len(rule["Resources"]) - RULES_INIT['Resources'][rule['ResourceGroup']]['Variation']
        number_of_resources_random = random.randint(min_nb_or_resources, len(rule["Resources"]))
        
        for id in range(0,number_of_resources_random):
            item["ResourceID"]=rule["Resources"][id]
            
            item["ComplianceType"] = []
            item["ComplianceType"].append("COMPLIANT")
            
            for prob in range(1,25):
                if item["ComplianceType"][prob-1] == "COMPLIANT" and random.random()<rule["ToNonCompliance"]:
                    item["ComplianceType"].append("NON_COMPLIANT")
                elif item["ComplianceType"][prob-1] == "NON_COMPLIANT" and random.random()<rule["ToCompliance"]:
                    item["ComplianceType"].append("COMPLIANT")
                else:
                    item["ComplianceType"].append(item["ComplianceType"][prob-1])
                if prob == 24:
                    if item["ComplianceType"][prob] == "NON_COMPLIANT":
                        final_compliance = "NON_COMPLIANT"

            
            
            #Push to Events
            increment_24_days = 0
            for increment_24_days in range(0, 1):            
                COUNT = COUNT + 24    
                event_to_sent={}
                event_to_sent["item"] = item
                event_to_sent["increment_24_days"] = increment_24_days
                lambda_client.invoke(FunctionName='GenerateData_PushBatchDynamoDB24items',InvocationType='Event',Payload=json.dumps(event_to_sent))
        
        #Push to Status Dynamo
        basetime = datetime(2017, 11, 30, 0, random.randint(1,59), random.randint(1,59), random.randint(1,999999))
        t = json.loads(json.dumps(basetime, default=datetime_handler))
        timestamp = str(t).split("T")[0]+ " " +str(t).split("T")[1]+"+00:00" 
        
        dynamodb.update_item(
            TableName='ComplianceStatusTable', 
            Key={
                'RuleARN':{'S':item["RuleARN"]}
                },
            UpdateExpression="set RecordedInDDBTimestamp =:t, LastResultRecordedTime = :le, AccountID = :a, RuleName =:n, ComplianceType =:c, AccountClassification =:ac, RuleCriticity =:rc",
            ExpressionAttributeValues={
                ':t': {'S':timestamp},
                ':le': {'S':timestamp},
                ':a': {'S':item["AccountID"]},
                ':n': {'S':item["RuleName"]},
                ':c': {'S':final_compliance},
                ':ac': {'S':item["AccountClassification"]},
                ':rc': {'S':item["RuleCriticity"]}
                }
            )

    return str(COUNT)