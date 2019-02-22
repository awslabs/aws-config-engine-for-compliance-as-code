# Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import json
import os
import datetime
import time
import boto3
import botocore

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

#############
# Main Code #
#############

def evaluate_compliance(event, context, configuration_item, valid_rule_parameters):
    """Form the evaluation(s) to be return to Config Rules

    Return either:
    None -- when no result needs to be displayed
    a string -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    a dictionary -- the evaluation dictionary, usually built by build_evaluation_from_config_item()
    a list of dictionary -- a list of evaluation dictionary , usually built by build_evaluation()

    Keyword arguments:
    event -- the event variable given in the lambda handler
    configuration_item -- the configurationItem dictionary in the invokingEvent
    valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

    Advanced Notes:
    1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
    2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
    3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
    """

    ###############################
    # Add your custom logic here. #
    ###############################
    compliance_account_id = context.invoked_function_arn.split(":")[4]
    compliance_account_region = context.invoked_function_arn.split(":")[3]
    compliance_account_partition = context.invoked_function_arn.split(":")[1]

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
        empty_json = s3_compliance.put_object(Bucket=TEMPLATE_BUCKET, Key=json_name)

        # Trigger the pipeline to deploy the default template.
        try:
            cp_compliance = get_client_from_role('codepipeline', role_arn_codepipeline, os.environ['MainRegion'])
        except:
            cp_compliance = get_client_from_role('codepipeline', role_arn_codepipeline)
        exec_pipeline = cp_compliance.start_pipeline_execution(name=CODEPIPELINE_NAME)
        return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="Unable to load most recent template from S3. Auto-deployment has been triggered.")

    #Get current Config Rule state and configuration from invoking account.
    config_rule_list = {}
    try:
        config_rule_list = get_all_rules()
    except Exception as e:
        # If we can't get the rule config, report "NON_COMPLIANT" compliance status.  Something is broken on the remote account side.
        return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="Unable to get status of Config Rules.")

    template_rules_detail = []
    # For each Config Rule resource in template, ensure critical params match current configuration.
    for k, resource in template["Resources"].items():
        if resource["Type"] == "AWS::Config::ConfigRule":
            rule_found = False
            for rule in config_rule_list:
                if rule["ConfigRuleName"] == resource["Properties"]["ConfigRuleName"]:
                    template_rules_detail.append(rule)
                    #The Rule Exists!  If there are any discrepancies in Source or Scope, account is NON_COMPLIANT.
                    rule_found = True
                    if "Scope" in resource["Properties"]:
                        if "Scope" not in rule:
                            return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Scope' configuration.")

                        if resource["Properties"]["Scope"] != rule["Scope"]:
                            return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Scope' configuration.")

                    if "Source" in resource["Properties"]:
                        if "Source" not in rule:
                            return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Source' configuration.")
                        if resource["Properties"]["Source"]["Owner"] != rule["Source"]["Owner"]:
                            return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Owner' configuration.")
                        if "SourceDetails" in resource["Properties"]["Source"]:
                            if "SourceDetails" not in rule["Source"]:
                                return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Source' configuration.")

                            if resource["Properties"]["Source"]["SourceDetails"] != rule["Source"]["SourceDetails"]:
                                return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'Source' configuration.")
                        if 'Fn::Sub' in resource["Properties"]["Source"]['SourceIdentifier']:
                            resource_lambda = resource["Properties"]["Source"]['SourceIdentifier']['Fn::Sub'].replace('${AWS::Partition}', compliance_account_partition).replace('${AWS::Region}', compliance_account_region).replace('${LambdaAccountId}', compliance_account_id)
                        else:
                            resource_lambda = resource["Properties"]["Source"]['SourceIdentifier']

                        if resource_lambda != rule["Source"]["SourceIdentifier"]:
                            return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") has an incorrect 'SourceIdentifier' configuration.")

                    #If there are any rules defined in CFN template that are not enabled, account is NON_COMPLIANT
                    if rule["ConfigRuleState"] != "ACTIVE":
                        return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+rule["ConfigRuleName"]+") is not active.")

            if not rule_found:
                #If we have gotten to the end of the rules in the config_rule_list and not found our template Rule it is missing.  Return NON_COMPLIANT.resource["Properties"]["ConfigRuleName"]
                return build_evaluation(invoking_account_id, "NON_COMPLIANT", event, annotation="The rule ("+resource["Properties"]["ConfigRuleName"]+") is not deployed.")

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

    return "COMPLIANT"

def get_all_compliance_evaluations(rule_name):
    all_eval_part = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, Limit=100)
    all_eval = []
    while True:
        for eva in all_eval_part['EvaluationResults']:
            all_eval.append(eva)
        if 'NextToken' in all_eval_part:
            next_token = all_eval_part['NextToken']
            all_eval_part = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(ConfigRuleName=rule_name, NextToken=next_token, Limit=100)
        else:
            break
    return all_eval

def get_all_rules():
    all_rules_part = AWS_CONFIG_CLIENT.describe_config_rules()
    all_rules = []
    while True:
        for rule in all_rules_part['ConfigRules']:
            all_rules.append(rule)
        if 'NextToken' in all_rules_part:
            next_token = all_rules_part['NextToken']
            all_rules_part = AWS_CONFIG_CLIENT.describe_config_rules(NextToken=next_token)
        else:
            break
    return all_rules

def get_client_from_role(service, role_arn, region=None):
    credentials = get_assume_role_credentials(role_arn)
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

def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """
    valid_rule_parameters = rule_parameters
    return valid_rule_parameters

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.

    Keyword arguments:
    ex -- Exception text
    """
    return  build_error_response(internalErrorMessage="Parameter value is invalid",
                                 internalErrorDetails="An ValueError was raised during the validation of the Parameter value",
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.

    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc

def build_evaluation_from_config_item(configuration_item, compliance_type, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on configuration change rules.

    Keyword arguments:
    configuration_item -- the configurationItem dictionary in the invokingEvent
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_ci = {}
    if annotation:
        eval_ci['Annotation'] = annotation
    eval_ci['ComplianceResourceType'] = configuration_item['resourceType']
    eval_ci['ComplianceResourceId'] = configuration_item['resourceId']
    eval_ci['ComplianceType'] = compliance_type
    eval_ci['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
    return eval_ci

####################
# Boilerplate Code #
####################

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'ScheduledNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configurationItem = result['configurationItems'][0]
    return convert_api_configuration(configurationItem)

# Convert from the API model to the original invocation model
def convert_api_configuration(configurationItem):
    for k, v in configurationItem.items():
        if isinstance(v, datetime.datetime):
            configurationItem[k] = str(v)
    configurationItem['awsAccountId'] = configurationItem['accountId']
    configurationItem['ARN'] = configurationItem['arn']
    configurationItem['configurationStateMd5Hash'] = configurationItem['configurationItemMD5Hash']
    configurationItem['configurationItemVersion'] = configurationItem['version']
    configurationItem['configuration'] = json.loads(configurationItem['configuration'])
    if 'relationships' in configurationItem:
        for i in range(len(configurationItem['relationships'])):
            configurationItem['relationships'][i]['name'] = configurationItem['relationships'][i]['relationshipName']
    return configurationItem

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    if is_oversized_changed_notification(invokingEvent['messageType']):
        configurationItemSummary = check_defined(invokingEvent['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configurationItemSummary['resourceType'], configurationItemSummary['resourceId'], configurationItemSummary['configurationItemCaptureTime'])
    elif is_scheduled_notification(invokingEvent['messageType']):
        return None
    return check_defined(invokingEvent['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem['configurationItemStatus']
    eventLeftScope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        print(str(ex))
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# This removes older evaluation (usually useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):

    cleaned_evaluations = []

    old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=event['configRuleName'],
        ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
        Limit=100)

    old_eval_list = []

    while True:
        for old_result in old_eval['EvaluationResults']:
            old_eval_list.append(old_result)
        if 'NextToken' in old_eval:
            next_token = old_eval['NextToken']
            old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
                ConfigRuleName=event['configRuleName'],
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
                Limit=100,
                NextToken=next_token)
        else:
            break

    for old_eval in old_eval_list:
        old_resource_id = old_eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        newer_founded = False
        for latest_eval in latest_evaluations:
            if old_resource_id == latest_eval['ComplianceResourceId']:
                newer_founded = True
        if not newer_founded:
            cleaned_evaluations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evaluations + latest_evaluations

# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT

    #print(event)
    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    try:
        valid_rule_parameters = evaluate_parameters(rule_parameters)
    except ValueError as ex:
        return build_parameters_value_error_response(ex)

    try:
        AWS_CONFIG_CLIENT = get_client('config', event)
        if invoking_event['messageType'] in ['ConfigurationItemChangeNotification', 'ScheduledNotification', 'OversizedConfigurationItemChangeNotification']:
            configuration_item = get_configuration_item(invoking_event)
            if is_applicable(configuration_item, event):
                compliance_result = evaluate_compliance(event, context, configuration_item, valid_rule_parameters)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return build_internal_error_response('Unexpected message type', str(invoking_event))
    except botocore.exceptions.ClientError as ex:
        if is_internal_error(ex):
            return build_internal_error_response("Unexpected error while completing API request", str(ex))
        return build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'], ex.response['Error']['Message'])
    except ValueError as ex:
        return build_internal_error_response(str(ex), str(ex))

    evaluations = []
    latest_evaluations = []

    if not compliance_result:
        latest_evaluations.append(build_evaluation(event['accountId'], "NOT_APPLICABLE", event, resource_type='AWS::::Account'))
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, str):
        if DEFAULT_RESOURCE_TYPE == 'AWS::::Account':
            evaluations.append(build_evaluation(event['accountId'], compliance_result, event))
        else:
            evaluations.append(build_evaluation_from_config_item(configuration_item, compliance_result))
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True

            if not missing_fields:
                latest_evaluations.append(evaluation)
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, dict):
        missing_fields = False
        for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)
    else:
        evaluations.append(build_evaluation_from_config_item(configuration_item, 'NOT_APPLICABLE'))

    # Put together the request that reports the evaluation status
    resultToken = event['resultToken']
    testMode = False
    if resultToken == 'TESTMODE':
        # Used solely for RDK test to skip actual put_evaluation API call
        testMode = True
    # Invoke the Config API to report the result of the evaluation
    AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=resultToken, TestMode=testMode)
    # Used solely for RDK test to be able to test Lambda function
    return evaluations

def is_internal_error(exception):
    return ((not isinstance(exception, botocore.exceptions.ClientError)) or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code'] or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internalErrorMessage, internalErrorDetails=None):
    return build_error_response(internalErrorMessage, internalErrorDetails, 'InternalError', 'InternalError')

def build_error_response(internalErrorMessage, internalErrorDetails=None, customerErrorCode=None, customerErrorMessage=None):
    error_response = {
        'internalErrorMessage': internalErrorMessage,
        'internalErrorDetails': internalErrorDetails,
        'customerErrorMessage': customerErrorMessage,
        'customerErrorCode': customerErrorCode
    }
    print(error_response)
    return error_response
