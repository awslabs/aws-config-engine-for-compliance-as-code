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

def lambda_handler(event, context):
    
    ddb_client = boto3.client("dynamodb")
    count = 0
    response = ddb_client.scan(TableName="ComplianceEventsTable")

    s3_client = boto3.client('s3')
    filename = '/tmp/' + 'dynamostatus'
    
    with open(filename, 'w', newline='') as myfile:
        
        fieldnames = ['AccountID', 'ComplianceType', 'RecordedInDDBTimestamp', 'RuleName', 'LastResultRecordedTime', 'RuleARN', 'ResourceID', 'ResourceType', 'AccountClassification', 'RuleCriticity']
        writer = csv.DictWriter(myfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        loop = True
        
        while loop:
            for item in response["Items"]:
                count = count + 1
                writer.writerow({
                    'AccountID': item["AccountID"]["S"], 
                    'ComplianceType': item["ComplianceType"]["S"], 
                    'RecordedInDDBTimestamp': item["RecordedInDDBTimestamp"]["S"].split(".")[0],  
                    'RuleName':item["RuleName"]["S"], 
                    'LastResultRecordedTime':item["LastResultRecordedTime"]["S"].split(".")[0],  
                    'RuleARN':item["RuleARN"]["S"],
                    'ResourceID':item["ResourceID"]["S"],
                    'ResourceType':item["ResourceType"]["S"],
                    'AccountClassification':item["AccountClassification"]["S"],
                    'RuleCriticity':item["RuleCriticity"]["S"]
                    })
            if "LastEvaluatedKey" in response:
                response = ddb_client.scan(TableName="ComplianceEventsTable", ExclusiveStartKey=response["LastEvaluatedKey"])
                print("New response")
            else:
                print("Loop Ends")
                loop = False        
        
    s3_client.upload_file(filename, os.environ["Bucket"], 'compliance_events.csv')
    return "Count: " + str(count)