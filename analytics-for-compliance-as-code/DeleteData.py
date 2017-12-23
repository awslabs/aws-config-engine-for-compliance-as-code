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
import time

def lambda_handler(event, context):
    
    dynamodb = boto3.client('dynamodb')
    dynamodb.delete_table(TableName='ComplianceEventsTable')
    dynamodb.delete_table(TableName='ComplianceStatusTable')
    while True:
        try:
            dynamodb.describe_table(TableName='ComplianceEventsTable')
            time.sleep(5)
        except:
            break
    
    while True:
        try:
            dynamodb.describe_table(TableName='ComplianceStatusTable')
            time.sleep(5)
        except:
            break
            
    dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'RuleARN',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'RecordedInDDBTimestamp',
                    'AttributeType': 'S'
                }
            ],
            TableName='ComplianceEventsTable',
            KeySchema=[
                {
                    'AttributeName': 'RuleARN',
                    'KeyType': 'HASH'
                },
                {
                    'AttributeName': 'RecordedInDDBTimestamp',
                    'KeyType': 'RANGE'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 500,
                'WriteCapacityUnits': 500
            }
        )

    dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'RuleARN',
                    'AttributeType': 'S'
                }
            ],
            TableName='ComplianceStatusTable',
            KeySchema=[
                {
                    'AttributeName': 'RuleARN',
                    'KeyType': 'HASH'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 50,
                'WriteCapacityUnits': 50
            }
        )