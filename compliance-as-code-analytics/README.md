  Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  or in the "license" file accompanying this file. This file is distributed 
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
  express or implied. See the License for the specific language governing 
  permissions and limitations under the License.

# Objectives of the package
Deploy the analytics component for the compliance-as-code engine to provide insights on the compliance status of AWS accounts and resources in a multi-account environment. 

## Key Features
1. Transform the data from DynamoDB to a CSV file ready for consomption by Amazon QuickSight
2. Generate a sample DataSet and put it in the DynamoDB table of the Compliance-as-code engine
3. Delete and recreate the DynamoDB Tables of the Compliance-as-code engine

# User Guide

## Initial Deployment

### Requirements
1. Deploy the main compliance-account-setup.yaml in the root of this repo.
2. Have the ability to execute CloudFormation template in the Compliance Account.

### In Compliance Account
1. Create a new bucket (ex. compliance-as-code-ruleset-112233445566) and note the name
2. Add the content of this repository directly in the S3 bucket (no folder). It is composed of 2 yaml templates, several *.zip files and one .json
3. Execute (in the same region) the CloudFormation: compliance-account-analytics-setup.yaml

### Set up Amazon QuickSight
See official documentation: http://docs.aws.amazon.com/quicksight/latest/user/welcome.html
Note: The sample manifest to create the Data Store in QuickSight is named "quicksight_manifest-events.json"

## Generate the CSV file
1. Invoke the lambda function named "csv_ComplianceEventsTable_to_s3"
2. Check the S3 bucket created as part of the initial deployment by the CloudFormation compliance-account-analytics-setup.yaml
3. You may add a scheduler to execute this lambda function (daily for example)

## Create a dashboard on Amazon QuickSight
### Prepare the data set
You need to create manually Calculated Fields.

Here's some useful Formula examples:

DataAge: dateDiff({RecordedInDDBTimestamp},now())

WeightedClassification: ifelse({AccountClassification} = "1-Sensitive",4,{AccountClassification} = "2-Confidential",3,{AccountClassification} = "3-Private",2,{AccountClassification} = "4-Public",1,0)

WeightedCriticality: ifelse({RuleCriticality} = "1_CRITICAL",4,{RuleCriticality} = "2_HIGH",3,{RuleCriticality} = "3_MEDIUM",2,{RuleCriticality} = "4_LOW",1,0)

ClassCriti: {WeightedClassification} * {WeightedCriticality}

### Create Visuals
The following are visual you can leverage. The format is:

Name of the Visual : type of QuickSight Visual - configuration of the Visual - filter on the Visual.

Number of AWS Accounts : KPI - Value: AccountID (Count Distinct) - Filter: DataAge = 0

Resources in all Accounts : Horizontal Stack Bar Chart - Y Axis: ResourceType; Value: ResourceID (Count Distinct) - Filter: DataAge = 0

Account Distribution by Account Classification : Horizontal Stack Bar Chart - Y Axis: AccountClassification; Value: AccountID (Count Distinct) - Filter: DataAge = 0

Rule Distribution by Rule Criticity : Horizontal Stack Bar Chart - Y Axis: RuleCriticality; Value: RuleName (Count Distinct) - Filter: DataAge = 0

Accounts with current Non-Compliant Rules by ClassCriti : Horizontal Stack Bar Chart - Y Axis: AccountID; Value: RuleName (Count Distinct) - Filter: DataAge = 0 & ClassCriti = [12,16]

Non-Compliance Events across all Resources by Account Classification : Line Chart - X Axis: RecordedInDDBTimestamp; Value: ResourceID (Count Distinct); Color: AccountClassification - Filter: DataAge = 0 & ComplianceType = "NON_COMPLIANT"

## Create a DataSample
1. Modify the GenerateData lambda function code (if needed). Make sure not to create more than 8 accounts at a time, otherwise the Lambda function may timeout.
2. Execute the GenerateData lambda function.
Those steps can be repeated in order to create more data sample.

