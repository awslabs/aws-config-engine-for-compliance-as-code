  Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
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
1. Get you started to get insights from your data using Amazon Athena
2. Generate a sample DataSet for you to be able to try/demonstrate the insights without deploying the engine in any account.

# User Guide

## Initial Deployment

### Requirements
1. Deploy the main compliance-account-setup.yaml in the root of this repo.
2. Have the ability to execute CloudFormation template in the Compliance Account.

### Set up the Compliance Account

#### No Demo
1. Execute (in the same region) the CloudFormation: compliance-account-analytics-setup.yaml
2. Execute the saved 3 Athena Queries that you can find in Athena > Saved Queries

#### Demo Mode
1. Create a new bucket (ex. compliance-as-code-ruleset-112233445566) and note the name
2. Add generate-compliance-events-data-samples.zip directly in the S3 bucket (no folder)
3. Execute (in the same region) the CloudFormation: compliance-account-analytics-setup.yaml
4. Execute the saved 3 Athena Queries that you can find in Athena > Saved Queries

## Set up Amazon QuickSight
See official documentation to import an Athena query in QuickSight: https://docs.aws.amazon.com/quicksight/latest/user/create-a-data-set-athena.html
* Make sure you add the Athena Results bucket and the original bucket in QuickSight settings.
* We recommend to use SPICE for best performance.
* Remember to add a scheduler to refresh the SPICE Data Set(s) daily

### Create a dashboard on Amazon QuickSight
#### Prepare the data set
Change the data type for the recordedinddbtimestamp & lastresultrecordedtime from String to Data: yyyy-MM-dd HH:mm:ss

You need to create manually Calculated Fields. Here's some useful Formula examples:

DataAge: dateDiff({recordedinddbtimestamp},now())

WeightedClassification: ifelse({accountclassification} = "1-Sensitive",4,{accountclassification} = "2-Confidential",3,{accountclassification} = "3-Private",2,{accountclassification} = "4-Public",1,0)

WeightedCriticity: ifelse({rulecriticity} = "1_CRITICAL",4,{rulecriticity} = "2_HIGH",3,{rulecriticity} = "3_MEDIUM",2,{rulecriticity} = "4_LOW",1,0)

ClassCriti: {WeightedClassification} * {WeightedCriticity}

#### Create Visuals
The following are visual you can leverage. The format is:

Name of the Visual : type of QuickSight Visual - configuration of the Visual - filter on the Visual.

##### Operational Metrics

60-day trend on Number of AWS Accounts by Classification : Line Chart - X Axis: DataAge; Value: AccountID (Count Distinct); Color: AccountClassification - Filter: DataAge <= 60

Accounts with Critical Non-Compliant Rules : Horizontal Stack Bar Chart - Y Axis: AccountID; Value: RuleName (Count Distinct) - Filter: DataAge <= 1 & ClassCriti = [12,16] & ComplianceType = "NON_COMPLIANT"

60-day trend on Non-compliant Rule by ClassCriti :  Line Chart - X Axis: DataAge; Value: AccountID (Count Distinct); Color: ClassCriti - Filter: DataAge <= 60

Resources in all Accounts : Horizontal Stack Bar Chart - Y Axis: ResourceType; Value: ResourceID (Count Distinct) - Filter: DataAge <= 1

Account Distribution by Account Classification : Horizontal Stack Bar Chart - Y Axis: accountclassification; Value: AccountID (Count Distinct) - Filter: DataAge = 0

Rule Distribution by Rule Criticity : Horizontal Stack Bar Chart - Y Axis: rulecriticity; Value: RuleName (Count Distinct) - Filter: DataAge <= 1

Non-Compliant Resources by RuleName and by ClassCriti : Heat Map - Row: RuleName ; Columns: ClassCriti; Values ResourceID (Count Distinct) - Filter: DataAge <= 1 & ComplianceType = "NON_COMPLIANT"

Trend of Non-Compliant Resources by Account Classification : Line Chart - X Axis: RecordedInDDBTimestamp; Value: ResourceID (Count Distinct); Color: accountclassification - Filter: ComplianceType = "NON_COMPLIANT"

List of Rules and Non-Compliant Resources: Table - Group by: rulename, resourceid; Value: ClassCriti (Max), AccountID (Count Distinct) - Filter: DataAge <= 1

##### Executive Metrics

Overall Compliance of Rules by Account Classification: Horizontal stacked 100% bar chart - Y axis: AccountClassification; Value: RuleArn (Count Distinct); Group/Color: ComplianceType - Filter: DataAge <= 1

Evolution of Compliance Status (last 50 days): Vertical stacked 100% bar chart - X axis: DataAge, Group/Color: ComplianceType - Filter: DataAge <= 50

Top 3 Account Non Compliant (weighted): Horizontal stacked bar chart - Y axis: AccountID , Value: DurationClassCriti (Sum), Group/Color: ClassCriti - Filter: ClassCriti >= 8

### Demo Mode - Create a DataSample
Initially, the Demo generate a 10-day history of data, then execute daily to keep a demo ready-to-go.
You may modify those parameters in the lambda function named: generate-compliance-events-data-samples
