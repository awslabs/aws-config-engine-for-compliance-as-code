# Engine for Compliance-as-code

This package is a collaborative project to deploy and operate Config Rules at scale in an multi-account environment. 

Please give feedback or bug report by email: jrault@amazon.com

## Objectives of the package
1. Deploy automatically and operate configurable sets of AWS Config Rules in a multi-account environment.
2. Provide insights and records on the compliance status of all AWS Accounts and resources.
3. Provide an initial set of recommended AWS Config Rules.

## Key Features
1. Analyze current situation and trends from the compliance account as all data are pushed in a Datalake.
2. Use your favorite analytics tool (Amazon QuickSight, Tableau, Splunk, etc.) as the data is formatted to be directly consumable.
3. Classify your AWS accounts to deploy only relevant Config Rules depending of your classification (e.g. application type, resilience, stage, sensitvity, etc.).
4. Ensure that the deployed Rules in each Account are always up-to-date.
5. Store all historical data of all the changes by storing the compliance record in a centralized and durable Amazon S3 bucket.
6. Deploy easily in 100s of accounts: by having a 1-step process for any new application account via AWS CloudFormation.
7. Protect the code base: by centralizing the code base of all the compliance-as-code rules in a dedicated "Compliance Account".
8. Make use of the AWS Config Rules Dashboard to display the details of compliance status of your AWS resources by setting up Config Aggregator. 
 
# Getting Started

## In a single AWS Region (in a single or multi-account environment)

You can follow the steps below to install the Compliance Engine. 

### Requirements
1. Define an AWS Account to be the central location for the engine (Compliance Account).
2. Define the AWS Accounts to be verified by the engine (Application Accounts). Note: the Compliance Account can be verified to.

### In the Compliance Account
1. Deploy compliance-account-initial-setup.yaml in your centralized account. Change the MainRegion parameter to match the region where you are deploying this template, if required.
2. Zip the 2 directories "rules/" and "rulesets-built/" into "ruleset.zip", including the directories themselves.
3. Copy the "ruleset.zip" in the source bucket (i.e. by default "compliance-engine-codebuild-source-**account_id**-**region_name**")
4. Go to CodePipeline, then locate the pipeline named "Compliance-Engine-Pipeline". Wait that it auto-triggers (it might show "Failed" when you check for the first time). 

### In the Application Accounts
1. Deploy application-account-initial-setup.yaml.

### Verify the deployment works
1. Verify in the Compliance Account that the CodePipeline pipeline named "Compliance-Engine-Pipeline" is executed succesfully
2. Verify in the Application Account that the Config Rules are deployed.

## In multiple AWS Region (in a single or multi-account environment)

1. Follow the "Getting Started" in a single AWS Region (above)
2. Follow the "Add a new Region" in the User Guide (below)

# FAQ
### What are the benefits to use of this Compliance engine?
This project assist you to manage, deploy and operate Config Rules in large AWS environment. It completely automate those tasks via a preconfigured pipeline. Additionally, it provides recommended Config Rules to be deployed as Security Baseline, mapped to the CIS Benchmark and PCI (named RuleSets).

### What is a RuleSet?
A RuleSet is a collection of Rules. For any AWS accounts, you can decide which RuleSet you want to deploy. For example, you might have a RuleSet for highly confidential accounts, or for high-available accounts or for particular standards (e.g. CIS, PCI or NIST).

### Can I add new Rules or new RuleSets?
Yes, we describe in the User Guide how to add new rules and new rulesets.

### What are the limits to expect from the Engine?
We expect the engine to work for 100s of accounts, we are yet to hit the limit. The limit for the number of rules per account is about 65 rules, due to CloudFormation template size limits. If interested for higher limits, please raise an issue or contact me: jrault@amazon.com.

### Does the engine support multi-region?
Yes, the engine is able to deploy different sets of rules between regions and accounts. By default, it deploys 2 different baselines of rules (avoid to deploy multiple rules with global scope only once, i.e. rules on AWS IAM). If interested to have more options for multi-region, please raise an issue or contact me: jrault@amazon.com.

### Does the engine use AWS Organizations?
No, for simplicity of the deployment and due to the multiple dimensions of each account we decided not to use AWS Organizations. If interested for using AWS Organizations, please raise an issue or contact me: jrault@amazon.com.

### I am already using AWS Config today. Can I still use the Engine?
Yes, the engine is compatible with an existing setup. 

# Overall Design

## High Level Design
The engine for compliance-as-code design has the following key elements:
- Application account(s): AWS account(s) which has a set of requirements in terms of compliance controls. The engine verifies the compliance controls implemented in this account.
- Compliance account: the AWS account which contains the code representing the compliance requirements. It should be a restricted environment. Notification, Historical data storage and reporting are driven from this account.

<img src="docs/images/engine_hl_design.png" alt="config-engine-high-level-design">

## Low Level Design

<img src="docs/images/engine_ll_design.png" alt="config-engine-low-level-design">

## RuleSets

The set of Rules deployed in each Aplication Account depends on:
- initial deployment of compliance-account-initial-setup.yaml: the parameter "DefaultRuleSet" in the CloudFormation template represents the default RuleSet to be deployed in any Application Accounts (main Region), not registered in account_list.json. For other regions (not the main Region), the parameter "DefaultRuleSetOtherRegions" in the CloudFormation template represents the default RuleSet to be deployed.
- account_list.json (optional): this file includes the metadata of the accounts and their classifications (via tags)
- rules/RULE_NAME/parameters.json: those files are included in each rule folder. Those rule metadata are matched with account metadata to deploy the proper Ruleset in each account.

## Deployment Flow
1. When a new Application Account is added via the application-account-initial-setup.yaml, one rule is installed (by default named COMPLIANCE_RULESET_LATEST_INSTALLED)
2. This rule verifies if the correct Config rules are installed.
3. If not, the rule create an empty *account_id*.json file to register, and it triggers the CodePipeline in the Compliance Account.
4. The pipeline looks at all accounts installed (all json file) and matches with their metadata stored in *account_list.json*.
5. If the account has no metadata (ie. not registered), the pipeline create a default template with the default ruleset (by default: baseline).
6. The pipeline then deploy the account-specific AWS Config Rules via CloudFormation in all AWS accounts (registered or not in account_list.json). 
7. The COMPLIANCE_RULESET_LATEST_INSTALLED rule is trigger every 24h (configurable) to verify that the installed ruleset is still current.

# User Guide

## Add a new Application Account in scope in 1 step

In Application Account, deploy (in the same region) the CloudFormation: application-account-initial-setup.yaml. 

This Cloudformation does the following:
- enable and centralize Config
- deploy an IAM role to allow the Compliance Engine to interact
- deploy 1 Config Rule, used for verifying that the proper Rules are deployed. If non-compliant, it will trigger automatically the deployment of an update.

After few minutes, all the Config Rules defined as "baseline" (configurable) will be deployed in this new Application Account.

## Add a whitelisted/exception resource from a particular Rule

Certain resources may have a business need to not follow a particular rule. You can whitelist a resouce from being NON_COMPLIANT in the datalake, where you can query the compliance data. The resource will be then be noted as COMPLIANT, and the flag "WhitelistedComplianceType" will be set to "True" for traceability.

To add a resource in the whitelist:

1. Update the file ./rulesets-build/compliance-whitelist.json (for model, there are dummy examples).
2. Ensure that the location of the whitelist is correct in the code ./rulesets-build/etl_evaluations.py
3. Ensure the WhitelistLocation parameter in compliance-account-initial-setup.yaml is correct

Note: the resource will still be shown non-compliant in the AWS console of Config Rules. 

Note 2: certain Rules might have a whitelist/exception in the parameters.json, but only for custom Config rules.

## Add a new Region

1. In the Compliance Account, update compliance-account-initial-setup.yaml adding the region in the OtherActiveRegions parameter. You can add several regions.
2. In the Compliance Account, deploy (in the additional region) the CloudFormation: compliance-account-initial-setup.yaml. No change is required in your original parameters.
2. Run the pipeline in the main region. It deploys the supporting infrastructure (including buckets and lambdas) in the other region of your Compliance Account.
3. In the Application Account, deploy (in the additional region) the CloudFormation: application-account-initial-setup.yaml. No change is required in your original parameters.

## Deploy Rules differently depending of AWS Accounts (in a single Region scenario)

This is an advanced scenario, where you want to deploy more than the default baseline. In this scenario, you can chose precisely which rule get deployed in which account(s) in the main Region.

### Add an Account list
1. Create an account_list.json, following the format:
```
{
	"AllAccounts": [{
		"Accountname": "Test Account 1",
		"AccountID": "123456789012",
		"OwnerEmail": ["admin1@domain.com"],
		"RootEmail" : "root1@domain.com",
        "Tags": ["baseline", "confidentiality:high"]
	}]
}
```
2. Update the compliance-account-initial-setup with the account list location

### Create the link between Account and Rules
The engine matches the Tags in the account_list.json with the Tags in the parameters.json of the Rules. When a match is detected, the Rule is deployed in the target account.

## Deploy rules differently depending of AWS Accounts and Regions (in a multiple Regions scenario)

This is an advanced scenario, where you want to deploy more than 2 different regional baselines. In this scenario, you can chose precisely which rule get deployed in which account(s) and in which region(s).

### Add an Account list
1. Create an account_list.json, following the format (notice the "Region" key):
```
{
	"AllAccounts": [{
		"Accountname": "Test Account 1",
		"AccountID": "123456789012",
		"OwnerEmail": ["admin1@domain.com"],
		"RootEmail" : "root1@domain.com",
        "Region": "us-west-1",
        "Tags": ["baseline", "confidentiality:high"]
	}, {
		"Accountname": "Test Account 1",
		"AccountID": "123456789012",
		"OwnerEmail": ["admin1@domain.com"],
		"RootEmail" : "root1@domain.com",
        "Region": "ap-southeast-1",
        "Tags": ["otherregionsbaseline", "confidentiality:high"]
	}]
}
```
2. Update the compliance-account-initial-setup with the account list location

### Create the link between Account and Rules
The engine matches the Tags in the account_list.json with the Tags in the parameters.json of the Rules. When a match is detected, the Rule is deployed in the target region of the account.

## Add a new Config Rule in a RuleSet

### Add a custom Rule to a RuleSet
1. Create the rule with the RDK (https://github.com/awslabs/aws-config-rdk)
2. Copy the entire RDK rule *folder* into the ./rules/ (including the 2 python files (code and test) and the parameters.json)
3. Use the RDK feature for "RuleSets" to add the rules to the appropriate RuleSet. By default, no RuleSet is configured. If you don't use the *account_list*.json, tag the rule with the value of the parameter "DefaultRuleSet" (the one in the CloudFormation template) to deploy in the main region and/or tag the rule with the value of the parameter "DefaultRuleSetOtherRegions" to deploy in the other region(s) (not main).

4. Add it into the "ruleset.zip" (see initial deployment section for details)
5. Run the CodePipeline pipeline named "Compliance-Engine-Pipeline"

### Add a managed Rule to a RuleSet
1. Follow the RDK instructions to add a Managed Rules in particular RuleSets. 
2. Add it into the "ruleset.zip" (see initial deployment section for details)
3. Run the CodePipeline pipeline named "Compliance-Engine-Pipeline"


## Visualize all the Compliance data using the Compliance-as-code Datalake

### Set up the Compliance Account

Execute the saved Athena Queries that you can find in Athena > Saved Queries
* 1-Database For ComplianceAsCode
* 2-Table For ComplianceAsCode
* 3-Table For Config in ComplianceAsCode
* 4-Table For AccountList (if account_list.json is configured)

### Set up Amazon QuickSight
See official documentation to import an Athena query in QuickSight: https://docs.aws.amazon.com/quicksight/latest/user/create-a-data-set-athena.html
* Make sure you add the Athena Results bucket and the original bucket in QuickSight settings.
* We recommend to use SPICE for best performance.
* Remember to add a scheduler to refresh the SPICE Data Set(s) daily

#### Prepare the data sets
Change the data type for the enginerecordedtime, resultrecordedtime & configruleinvokedtime from String to Data: yyyy-MM-dd HH:mm:ss

You need to create manually Calculated Fields. Here's some useful Formula examples:

DataAge: dateDiff({enginerecordedtime},now())

Confidentiality: ifelse(isNull({accountid[accountlist]}),"NOT REGISTERED",toUpper(split({tag2},":",2)))

WeightedConfidentiality: ifelse({Confidentiality} = "HIGH",3,{Confidentiality} = "MEDIUM",2,{Confidentiality} = "LOW",1,0)

WeightedRuleCriticity: ifelse({rulecriticity} = "1_CRITICAL",4,{rulecriticity} = "2_HIGH",3,{rulecriticity} = "3_MEDIUM",2,{rulecriticity} = "4_LOW",1,0)

ClassCriti: {WeightedClassification} * {WeightedRuleCriticity}

KinesisProcessingError: ifelse(isNull({configrulearn}),"ERROR", "OK")

### Create Compliance dashboard on Amazon QuickSight
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

# Team
* Jonathan Rault - Current maintainer
* Michael Borchert - Design, Coding and Feedback

# License
This project is licensed under the Apache 2.0 License

# Acknowledgments
* The RDK team makes everything so much smoother.

# Related Projects
* Rule Development Kit (https://github.com/awslabs/aws-config-rdk)
* Rules repository (https://github.com/awslabs/aws-config-rules)
