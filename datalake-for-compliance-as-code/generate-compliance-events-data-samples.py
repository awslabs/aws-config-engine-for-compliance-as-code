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

import boto3
import csv
import os
import json
import copy
import random
import gzip
from datetime import datetime, date, timezone, tzinfo, timedelta
import string

global RULES_INIT

KEY_DATABASE_NAME = "database-sample-data.json"
NUMBER_OF_DAYS = 10
    
RULES_INIT = {
        'Account': {
            'NumberOfSensitive': 12,
            'NumberOfConfidential': 20,
            'NumberOfPrivate': 15,
            'NumberOfPublic': 13
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
    
def generate_account_by_sensitivity():
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

def daterange(start_date, end_date):
    for n in range(int ((end_date - start_date).days)):
        yield start_date + timedelta(n)
        
def get_account_classification(account_id, database):
    for account in database["Accounts"]:
        if account_id == account["AccountID"]:
            return account["AccountClassification"]
 
def get_rule_arn(rulename, account_id, database):
    for rule in database["Rules"][account_id]:
        if rulename == rule["RuleName"]:
            return rule["RuleARN"]
            
def generate_daily_dataset(date, database):
  
    date_str = date.strftime("%Y-%m-%d")
    
    file_suffix = "part-00001.gz"
    s3_filename = "compliance-events/"+ str(date.year) +"/"+ date.strftime("%m") +"/"+ date.strftime("%d") +"/"+"00/"+file_suffix
    local_filename = "/tmp/"+ str(date.day)+ "-" + file_suffix
    s3_client = boto3.client('s3')

    print ("Generating data for date: " + date_str + " into file:" + local_filename)

    count = 0
        
    with gzip.open(local_filename, 'wt', encoding='utf8') as myfile:

        for rule in RULES_INIT["Rules"]:
            for resource in database["Resources"][rule["ResourceGroup"]]:
                if RULES_INIT['Resources'][rule['ResourceGroup']]['ResourceType']==resource['Type']:    
                    new_item = {}
                    new_item["RuleARN"]=get_rule_arn(rule["RuleName"], resource["Account"], database)
                    new_item["RecordedInDDBTimestamp"]=str(date.strftime("%Y-%m-%d %H:%M:%S"))
                    new_item["RuleName"]=rule["RuleName"]
                    new_item["ResourceType"]=resource["Type"]
                    new_item["ResourceId"]=resource["Id"]
                    if random.random() > 0.8:    
                        new_item["ComplianceType"]="NON_COMPLIANT"
                    else:
                        new_item["ComplianceType"]="COMPLIANT"
                    new_item["LastResultRecordedTime"]=str(date.strftime("%Y-%m-%d %H:%M:%S"))
                    new_item["AccountID"]=resource["Account"]
                    new_item["AccountClassification"]=get_account_classification(resource["Account"], database)
                    new_item["RuleCriticity"] = rule["RuleCriticity"]

                    json.dump(new_item, myfile)
                    myfile.write('\n')
    
    s3_client.upload_file(local_filename, os.environ['Bucket'] , s3_filename)
            
def generate_initial_dataset(days):
    # Generate data for the days before
    
    s3_client = boto3.client('s3')
    '''
    start_date = EXPORT_START_DATE_INCLUDED
    end_date = EXPORT_END_DATE_NOT_INCLUDED
    '''
    return
    
def generate_resources_for_all_accounts(account_list):
    
    group_of_resource = {}
    for y in range(0, len(RULES_INIT['Resources'])):
        group_of_resource['Group'+str(y+1)]=[]
    
    for account in account_list:        
        for y in range(0, len(RULES_INIT['Resources'])):
            group = RULES_INIT['Resources']['Group'+str(y+1)]
            number_of_resources = random.randint(group['MinNumberOfResouces'],group['MaxNumberOfResouces'])
            for x in range(0,number_of_resources):
                group_of_resource['Group'+str(y+1)].append({
                        "Id":generate_resource(group['ResourceType'], account["AccountID"]),
                        "Type":RULES_INIT['Resources']['Group'+str(y+1)]["ResourceType"],
                        "Account":account["AccountID"]
                    })
    return group_of_resource

def generate_rulearn_for_all_accounts(account_list):
    group_of_rules = {}
    for account in account_list:
        group_of_rules[account["AccountID"]] = []
        for rule in RULES_INIT['Rules']:
            group_of_rules[account["AccountID"]].append({
                "RuleName":rule['RuleName'],
                "RuleARN":generate_resource("AWS::Config::ConfigRule", account["AccountID"])
                })
    return group_of_rules
   
def generate_database():
    database = {}
    database["Accounts"] = generate_account_by_sensitivity() 
    database["Resources"] = generate_resources_for_all_accounts(database["Accounts"])
    database["Rules"] = generate_rulearn_for_all_accounts(database["Accounts"])
        
    file_suffix = "database-sample-data.json"
    s3_filename = file_suffix
    local_filename = "/tmp/"+ file_suffix
    s3_client = boto3.client('s3')
    
    with open(local_filename, 'w', newline='') as myfile:
        json.dump(database, myfile)
        myfile.write('\n')
        
    s3_client.upload_file(local_filename, os.environ["Bucket"], s3_filename)
      
    
def lambda_handler(event, context):
   
    s3 = boto3.resource('s3')
        
    try:
        obj = s3.Object(os.environ['Bucket'], KEY_DATABASE_NAME)
        database = json.loads(obj.get()['Body'].read().decode('utf-8'))
        timestamp_now = datetime.now()
        generate_daily_dataset(timestamp_now, database)
    except Exception as e:
        print(e)
        generate_database()
        obj = s3.Object(os.environ['Bucket'], KEY_DATABASE_NAME)
        database = json.loads(obj.get()['Body'].read().decode('utf-8'))
        timestamp_now = datetime.now()
        print(timestamp_now - timedelta(days=NUMBER_OF_DAYS))
        for single_date in daterange(timestamp_now - timedelta(days=NUMBER_OF_DAYS), timestamp_now):
            generate_daily_dataset(single_date, database)
        generate_daily_dataset(timestamp_now, database)
       
    return "DONE"