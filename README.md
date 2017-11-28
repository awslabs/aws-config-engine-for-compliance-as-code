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
Deploy a compliance-as-code engine to provide insights on the compliance status of AWS accounts and resources in a multi-account environment. In addition of the engine, a set of Rules can be deployed and is customizable depending on your enviroment. The set of Rules is named a RuleSet.

## Key Features
1. Protect the code base: by centralizing the code base of all the compliance-as-code rules in an “compliance account”.
2. Keep the cost effective approach by using describes and limiting the number of individual Config rules.
3. Deploy easily in 10s of accounts: by having a 1-step process for each new application account via CFn.
4. Adapt the RuleSet to the type of environment of the application: by specifying a single parameter during the deployment in the application account.
5. Store all historical data of all the changes by storing the compliance record in a centralized DynamoDB 
6. Store the current state of each rule of the application accounts in a centralized DynamoDB
7. Display aggregate results in compliance account by using what the service team is building
8. Display the details of non-compliant item directly in Config rule dashboard
9. Notify on non-compliant item by triggering an SNS topic

## Provided RuleSets with the Engine
* ruleset-security-epics-baseline (Up to 16 rules - 30 controls)
* ruleset-pci-guidance-8-rules (Up to 8 rules - 8 controls)
See the details of each RuleSet in the "application-account-ruleset-*" files.

# User Guide

## Initial Deployment

### Requirements
1. Define a Compliance Account and an Application Account for POC.
2. Have the ability to execute CloudFormation templates in all the accounts.

### In Compliance Account
1. Create a new bucket (ex. compliance-as-code-ruleset-112233445566) and note the name
2. Add the content of repository named "ruleset-..." directly in the S3 bucket (no folder). It is composed of 2 yaml templates and several *.zip files
3. Execute (in the same region) the Cloudformation: compliance-account-setup.yaml
4. Note the name of the centralized bucket you selected when launching the above CloudFormation (ex. centralized-config-112233445566)

## Add a new Application account in scope

In Application Account, execute (in the same region) the Cloudformation: application-account-ruleset-...-setup.yaml

Note 1: Depending on your selection for the enviroment type, the template will deploy diferent rules.

Note 2: You can add the Compliance Account as an Application account. The compliance Account then checks the compliance of itself.

## Visualize all the data in the Compliance Account

Two DynamoDB tables stores the current and past value for all your accounts
- ComplianceStatusTable : Latest reported status
- ComplianceEventsTable : All reported events

# Developer Guide

## Create a new RuleSet
1. Duplicate an existing RuleSet (Directory and application-account-ruleset-...-setup.yaml)
2. Follow the instruction below to Add a new Rule to the RuleSet

## Add an SNS topic to be triggered
1. Create an SNS topic in the Compliance Account.
2. Deploy the Initial Deployment of the Compliance Account 
3. Modify "Ruleset_Status_Reporter" lambda function code to add the ARN of the SNS topic. 

## Add a new Rule to the RuleSet

### Adding a Managed Config Rules

#### Step 1: Modify in application-account-ruleset-...-setup.yaml

In the Resource section, add the Config rule (see existing RuleSets).

#### Step 2: Deploy the new Rule

In each Application Account, update the CloudFormation stack
- application-account-setup

### Adding a Custom Config Rules to the RuleSet

#### Step 1: Modify ruleset-.../compliance-account-ruleset-setup.yaml

In the Resource section, add a new stack with the proper configuration (see existing RuleSets).

#### Step 2: Modify application-account-ruleset-...-setup.yaml

In the Resource section, add the config rule (example provided in the sample RuleSet)

#### Step 3: Deploy the new Rule

##### Step 3.1: In Compliance Account

1. Upload in the S3 bucket you initiatilly created (Initial deployment - 1.), the following:
- compliance-account-ruleset-setup.yaml
- new-rule.zip

Note: the name of the code file must be the same as the zipped file, except the extension. The name defined in the yaml templates modified in Step 1 and Step 2 must be as well the same

2. Update the CloudFormation stack:
- compliance-account-setup.yaml

##### Step 3.2: In each Application Account

Update the CloudFormation stack:
- application-account-ruleset-*****-setup.yaml


