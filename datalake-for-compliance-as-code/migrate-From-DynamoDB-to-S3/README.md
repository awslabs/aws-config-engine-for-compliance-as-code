  Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  or in the "license" file accompanying this file. This file is distributed 
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
  express or implied. See the License for the specific language governing 
  permissions and limitations under the License.

# Objectives
A previous version of the Engine for Compliance-as-code was using a DynamoDB to store the Compliance Events. You can find attached a lambda function to migrate from DynamoDB to S3.

# User Guide

1. Increase the DynamoDB read capacity to 1000
2. Create a lambda function in Python2.7 with the code present in MigrationFromDDBtoS3.py
3. Set up the timeout to 300 seconds
4. Modify appropriately the variable S3_BUCKET_NAME_TO_STORE_COMPLIANCE_EVENT in MigrationFromDDBtoS3.py
5. Setup the variables: EXPORT_START_DATE_INCLUDED and EXPORT_END_DATE_NOT_INCLUDED. Note: depending on the number of account, the lambda will timeout if you move to many data at once. When it fails, you can see in the logs until which day it succeeded.
6. Execute the function (no particular event needed)
7. Repeat as many time as necessary by changing the variables: EXPORT_START_DATE_INCLUDED and EXPORT_END_DATE_NOT_INCLUDED.
8. Decrease Dynamo read capacity.
9. Once you are confident that Dynamo is not used, you may delete it.
