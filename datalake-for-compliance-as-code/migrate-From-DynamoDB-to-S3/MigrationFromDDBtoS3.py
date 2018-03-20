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
import json
import os
import gzip
from datetime import timedelta, date, datetime
from boto3.dynamodb.conditions import Key, Attr

########################
# PARAMETERS to modify #
########################
S3_BUCKET_NAME_TO_STORE_COMPLIANCE_EVENT = "compliance-events-centralized-123456789012"
EXPORT_START_DATE_INCLUDED = date(2018, 3, 5)
EXPORT_END_DATE_NOT_INCLUDED = date(2018, 3, 16)

########
# Code #
########
def daterange(start_date, end_date):
    for n in range(int ((end_date - start_date).days)):
        yield start_date + timedelta(n)

def lambda_handler(event, context):

    s3_client = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('ComplianceEventsTable')
    
    start_date = EXPORT_START_DATE_INCLUDED
    end_date = EXPORT_END_DATE_NOT_INCLUDED
    
    for single_date in daterange(start_date, end_date):
        date_str = single_date.strftime("%Y-%m-%d")
    
        file_suffix = "part-00001.gz"
        s3_filename = "compliance-events/"+ str(single_date.year) +"/"+ single_date.strftime("%m") +"/"+ single_date.strftime("%d") +"/"+"00/"+file_suffix
        local_filename = "/tmp/"+ str(single_date.day)+ "-" + file_suffix

        print ("Exporting data for date: " + date_str + " into file:" + local_filename)
    
        count = 0
    
        # fe = Attr('RecordedInDDBTimestamp').contains(date_str)
        # response = table.scan(FilterExpression=fe)
        kce = Key('RecordedInDDBTimestamp').begins_with(date_str)
    
        with gzip.open(local_filename, 'wb') as myfile:
    
            response = table.scan(FilterExpression=kce)
            while True:
        
                for item in response["Items"]:
                    count = count + 1
                    # print(item["RecordedInDDBTimestamp"])
                    if 'RuleCriticality' not in item:
                        do_nothing=1
                        # print('No RuleCriticality on RuleName = '+ item["RuleName"] + ' ; RuleARN = ' + item["RuleARN"])
                    else:
                        new_item = {}
                        orig_date = item['LastResultRecordedTime']
                        if not str(orig_date).__contains__("."):
                            odo = datetime.strptime(orig_date, "%Y-%m-%d %H:%M:%S+00:00")
                            ndstr = odo.strftime("%Y-%m-%d %H:%M:%S.%f+00:00")
                            item['LastResultRecordedTime'] = ndstr
                        new_item['RuleARN']=item['RuleARN']
                        new_item['RecordedInDDBTimestamp']=item['RecordedInDDBTimestamp'].split(".")[0].split("+")[0]
                        new_item['RuleName']=item['RuleName']
                        new_item['ResourceType']=item['ResourceType']
                        new_item['ResourceId']=item['ResourceID']
                        new_item['ComplianceType']=item['ComplianceType']
                        new_item['LastResultRecordedTime']=item['LastResultRecordedTime'].split(".")[0].split("+")[0]
                        new_item['AccountID']=item['AccountID']
                        new_item['AccountClassification']=item['AccountClassification']
                        new_item['RuleCriticity'] = item['RuleCriticality']
                        
                        json.dump(new_item, myfile)
                        myfile.write('\n')
         
                if 'LastEvaluatedKey' in response :
                    response = table.scan(FilterExpression=kce, ExclusiveStartKey=response['LastEvaluatedKey'])
                else :
                    break
    
        print("\n total records found"+ str(count))
        
        if count>0:
            s3_client.upload_file(local_filename, S3_BUCKET_NAME_TO_STORE_COMPLIANCE_EVENT , s3_filename)
