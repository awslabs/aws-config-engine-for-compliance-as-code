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

def generate_time(base, day_increment):
    delay = float(day_increment*24*3600)
    dt = timedelta(seconds=delay)
    then = base + dt
    return then
    
def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")
    
def push_1_day(basetime, item, increment_24_days):

    dynamodb = boto3.client('dynamodb')
    ExpressionAttribute = []   
    NumberOfItemToWrite = 24
    for y in range(0, NumberOfItemToWrite):

        t = generate_time(basetime, y+increment_24_days*NumberOfItemToWrite)
        t = json.loads(json.dumps(t, default=datetime_handler))
        timestamp = str(t).split("T")[0]+ " " +str(t).split("T")[1]+"+00:00" 
        
        dict = {
                    'PutRequest': {
                        'Item': {
                            'RuleARN':{'S':item["RuleARN"]},
                            'RecordedInDDBTimestamp':{'S':timestamp},
                            'RuleName': {'S':item["RuleName"]},
                            'ResourceType': {'S':item["ResourceType"]},
                            'ResourceID': {'S':item["ResourceID"]},
                            'ComplianceType': {'S':item["ComplianceType"][y+increment_24_days*NumberOfItemToWrite]},
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
    
    basetime = datetime(2017, 11, 7, 0, random.randint(1,59), random.randint(1,59), random.randint(1,999999))
    
    push_1_day(basetime, event["item"], event["increment_24_days"])