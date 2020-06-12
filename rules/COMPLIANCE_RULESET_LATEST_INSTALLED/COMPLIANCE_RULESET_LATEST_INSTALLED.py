# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, ClientFactory
from rdklib.clientfactory import get_assume_role_credentials
import json
import os
import datetime
import time
import boto3

##############
# Parameters #
##############

# Define the Bucket prefix where the ruleset template are posted in the Compliance Account.
BUCKET_PREFIX = 'compliance-engine-codebuild-output'
DEFAULT_TEMPLATE = 'default.json'

# Role Arn of the CodePipeline, assumed to allow the lambda to trigger auto-deployment of the default template
ROLE_NAME_CODEPIPELINE = 'ComplianceEngine-CodePipelineRole'
CODEPIPELINE_NAME = 'Compliance-Engine-Pipeline'

# Name of the Firehose to record all evaluations of all the rules in all accounts
FIREHOSE_NAME = 'Firehose-Compliance-Engine'

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = True

# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900

#############
# Main Code #
#############

class COMPLIANCE_RULESET_LATEST_INSTALLED(ConfigRule):
    context = None

    def setContext(self, context):
        self.context = context

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        """Form the evaluation(s) to be return to Config Rules

        Return either:
        None -- when no result needs to be displayed
        a list of Evaluation -- a list of evaluation object , built by Evaluation()

        Keyword arguments:
        event -- the event variable given in the lambda handler
        client_factory -- ClientFactory object to be used in this rule. It is defined in RDKLib.
        valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

        Advanced Notes:
        1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
        2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
        3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
        """

        ###############################
        # Add your custom logic here. #
        ###############################
        compliance_account_id = self.context.invoked_function_arn.split(":")[4]
        compliance_account_region = self.context.invoked_function_arn.split(":")[3]
        compliance_account_partition = self.context.invoked_function_arn.split(":")[1]

        global config_client
        config_client=client_factory.build_client('config')

        TEMPLATE_BUCKET = "-".join([BUCKET_PREFIX, compliance_account_id, compliance_account_region])
        invoking_account_id = event["accountId"]

        #Load relevant CFN template into dict.
        template = {}
        json_name = invoking_account_id+".json"
        role_arn_codepipeline = "arn:aws:iam::" + compliance_account_id + ":role/" + ROLE_NAME_CODEPIPELINE
        try:
            s3 = boto3.resource('s3')
            obj = s3.Object(TEMPLATE_BUCKET, json_name)
            try:
                template = json.loads(obj.get()['Body'].read().decode('utf-8'))
            except Exception as e:
                if "Expecting value: line 1 column 1 (char 0)" in str(e):
                    obj_default = s3.Object(TEMPLATE_BUCKET, DEFAULT_TEMPLATE)
                    template = json.loads(obj_default.get()['Body'].read().decode('utf-8'))
                else:
                    raise
        except Exception as e:
            # If we can't get the template, report "NON_COMPLIANT" compliance status - either there is an issue with the json or it is the first time we see this account.
            # Create an empty json
            s3_compliance = get_client_from_role('s3', role_arn_codepipeline)
            s3_compliance.put_object(Bucket=TEMPLATE_BUCKET, Key=json_name)

            # Trigger the pipeline to deploy the default template.
            try:
                cp_compliance = get_client_from_role('codepipeline', role_arn_codepipeline, os.environ['MainRegion'])
            except:
                cp_compliance = get_client_from_role('codepipeline', role_arn_codepipeline)
            exec_pipeline = cp_compliance.start_pipeline_execution(name=CODEPIPELINE_NAME)
            return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="Unable to load most recent template from S3. Auto-deployment has been triggered. Execution Id: ["+exec_pipeline["pipelineExecutionId"]+"]")

        #Get current Config Rule state and configuration from invoking account.
        config_rule_list = {}
        try:
            config_rule_list = get_all_rules()
        except Exception as e:
            # If we can't get the rule config, report "NON_COMPLIANT" compliance status.  Something is broken on the remote account side.
            return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="Unable to get status of Config Rules.")

        template_rules_detail = []
        # For each Config Rule resource in template, ensure critical params match current configuration.
        for _, resource in template["Resources"].items():
            if resource["Type"] == "AWS::Config::ConfigRule":
                rule_found = False
                for rule in config_rule_list:
                    if rule["ConfigRuleName"] == resource["Properties"]["ConfigRuleName"]:
                        template_rules_detail.append(rule)
                        #The Rule Exists!  If there are any discrepancies in Source or Scope, account is NON_COMPLIANT.
                        rule_found = True
                        if "Scope" in resource["Properties"]:
                            if "Scope" not in rule:
                                return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Scope' configuration.")

                            if resource["Properties"]["Scope"] != rule["Scope"]:
                                return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Scope' configuration.")

                        if "Source" in resource["Properties"]:
                            if "Source" not in rule:
                                return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Source' configuration.")
                            if resource["Properties"]["Source"]["Owner"] != rule["Source"]["Owner"]:
                                return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Owner' configuration.")
                            if "SourceDetails" in resource["Properties"]["Source"]:
                                if "SourceDetails" not in rule["Source"]:
                                    return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Source' configuration.")

                                if resource["Properties"]["Source"]["SourceDetails"] != rule["Source"]["SourceDetails"]:
                                    return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Source' configuration.")
                            if 'Fn::Sub' in resource["Properties"]["Source"]['SourceIdentifier']:
                                resource_lambda = resource["Properties"]["Source"]['SourceIdentifier']['Fn::Sub'].replace('${AWS::Partition}', compliance_account_partition).replace('${AWS::Region}', compliance_account_region).replace('${LambdaAccountId}', compliance_account_id)
                            else:
                                resource_lambda = resource["Properties"]["Source"]['SourceIdentifier']

                            if resource_lambda != rule["Source"]["SourceIdentifier"]:
                                return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'SourceIdentifier' configuration.")

                        #If there are any rules defined in CFN template that are not enabled, account is NON_COMPLIANT
                        if rule["ConfigRuleState"] != "ACTIVE":
                            return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+rule["ConfigRuleName"]+") is not active.")

                if not rule_found:
                    #If we have gotten to the end of the rules in the config_rule_list and not found our template Rule it is missing.  Return NON_COMPLIANT.resource["Properties"]["ConfigRuleName"]
                    return Evaluation(ComplianceType.NON_COMPLIANT, invoking_account_id, annotation="The rule ("+resource["Properties"]["ConfigRuleName"]+") is not deployed.")

        #If we've gotten to the end of the template and everything looks good, we can record the results then return a COMPLIANT result.
        try:
            kinesis_client = get_client_from_role('firehose', role_arn_codepipeline, os.environ['MainRegion'])
        except:
            kinesis_client = get_client_from_role('firehose', role_arn_codepipeline)

        for rule in template_rules_detail:
            rule_evaluations = get_all_compliance_evaluations(rule["ConfigRuleName"])
            time.sleep(1) # To avoid throttling
            for result_id in rule_evaluations:
                # Record in Kinesis Firehose
                json_result = {
                    "ConfigRuleArn": rule['ConfigRuleArn'],
                    "EngineRecordedTime": str(datetime.datetime.now()).split(".")[0].split("+")[0],
                    "ConfigRuleName": rule["ConfigRuleName"],
                    "ResourceType": result_id['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'],
                    "ResourceId": result_id['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'],
                    "ComplianceType": result_id['ComplianceType'],
                    "ResultRecordedTime": str(result_id['ResultRecordedTime']).split(".")[0].split("+")[0],
                    "ConfigRuleInvokedTime": str(result_id['ConfigRuleInvokedTime']).split(".")[0].split("+")[0],
                    "AccountId": invoking_account_id,
                    "AwsRegion": rule['ConfigRuleArn'].split(":")[3]
                }
                if 'Annotation' in result_id:
                    json_result["Annotation"] = result_id['Annotation']
                else:
                    json_result["Annotation"] = "None"
                kinesis_client.put_record(
                    DeliveryStreamName=FIREHOSE_NAME,
                    Record={
                        'Data': json.dumps(json_result)
                    }
                )

        return [Evaluation(ComplianceType.COMPLIANT, invoking_account_id, DEFAULT_RESOURCE_TYPE)]

def get_all_compliance_evaluations(rule_name):
    all_eval_part = config_client.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, Limit=100)
    all_eval = []
    while True:
        for eva in all_eval_part['EvaluationResults']:
            all_eval.append(eva)
        if 'NextToken' in all_eval_part:
            next_token = all_eval_part['NextToken']
            all_eval_part = config_client.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, NextToken=next_token, Limit=100)
        else:
            break
    return all_eval

def get_all_rules():
    all_rules_part = config_client.describe_config_rules()
    all_rules = []
    while True:
        for rule in all_rules_part['ConfigRules']:
            all_rules.append(rule)
        if 'NextToken' in all_rules_part:
            next_token = all_rules_part['NextToken']
            all_rules_part = config_client.describe_config_rules(NextToken=next_token)
        else:
            break
    return all_rules

def get_client_from_role(service, role_arn, region=None):
    credentials = get_assume_role_credentials(role_arn, region=None)
    if not region:
        return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken']
                            )
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=region
                        )

################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = COMPLIANCE_RULESET_LATEST_INSTALLED()
    # set Context for  configRule object to obtain compliance account information
    my_rule.setContext(context)
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
