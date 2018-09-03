import base64
import json
import datetime
import os
import zipfile
import boto3

# DEFINE WHITELIST & RULESET LOCATION
# Define the Bucket prefix where the ruleset.zip and whitelist are posted in the Compliance Account.
BUCKET_PREFIX = 'compliance-engine-codebuild-source'
ORIGINAL_ZIP_RULES = 'ruleset.zip'
ORIGINAL_ZIP_RULES_FOLDER = 'rules'
FILE_NAME_RULE_PARAMETER = 'parameters.json'

# RULESET PARAMETERS
# Define the delimiter in the ruleset.txt
BUCKET_PREFIX_RULESET_TXT = 'compliance-engine-codebuild-output'
RULESET_LIST = 'rulesets_list.txt'
DELIMITER_IN_RULESET_LIST = ' '
TITLE_IN_RDK_RULESET = 'RuleSets:'
DELIMITER_IN_RULESET = ':'
DELIMITER_MULTI = ','

# KEEPING ATHENA QUERIES UP TO DATE
CODEBUILD_TEMPLATE_NAME = 'Compliance-Rule-Template-Build'
CODEPIPELINE_NAME = 'Compliance-Engine-Pipeline'

S3_CLIENT = boto3.client('s3')

def is_compliance_result_whitelisted(result):
    try:
        whitelist_key = os.environ['ComplianceWhitelist']
        if whitelist_key == 'none':
            return False
        bucket_wl = whitelist_key.split("/")[0]
        key_wl = "/".join(whitelist_key.split("/")[1:])
        object_wl = S3_CLIENT.get_object(Bucket=bucket_wl, Key=key_wl)
        whitelist_json = json.loads(object_wl["Body"].read().decode("utf-8"))

        for whitelist_item in whitelist_json["Whitelist"]:
            if whitelist_item["ConfigRuleArn"] == result["ConfigRuleArn"]:
                for whitelisted_resources in whitelist_item["WhitelistedResources"]:
                    if result["ResourceId"] in whitelisted_resources["ResourceIds"] \
                    and whitelisted_resources["ApprovalTicket"] \
                    and datetime.datetime.today().date() <= datetime.datetime.strptime(whitelisted_resources["ValidUntil"], '%Y-%m-%d').date():
                        print(result["ResourceId"] + " whitelisted for " + result["ConfigRuleArn"] + ".")
                        return True
        return False
    except Exception as ex:
        print("Whitelisting review went wrong: {}".format(str(ex)))
        return False

def download_rules_parameters_locally(bucket):
    s3_resource = boto3.resource('s3')
    local_file_name = '/tmp/' + ORIGINAL_ZIP_RULES
    s3_resource.Bucket(bucket).download_file(ORIGINAL_ZIP_RULES, local_file_name)

    with zipfile.ZipFile(local_file_name, 'r') as zip_ref:
        zip_ref.extractall('/tmp/')

    return True

def get_ruleset_definition(bucket):
    object_rs = S3_CLIENT.get_object(Bucket=bucket, Key=RULESET_LIST)
    ruleset_str = object_rs["Body"].read().decode("utf-8")
    ruleset_list_unprocessed = ruleset_str.replace('\n', ' ').split(DELIMITER_IN_RULESET_LIST)
    ruleset_list = []

    for ruleset in ruleset_list_unprocessed:
        ruleset_details_dict = {}
        if ruleset in [TITLE_IN_RDK_RULESET, '']:
            continue

        if DELIMITER_IN_RULESET in ruleset:
            ruleset_details = ruleset.split(DELIMITER_IN_RULESET)
            ruleset_details_dict["RulesetName"] = ruleset_details[0]
            ruleset_details_dict["MultiValue"] = True
            if ruleset_details_dict not in ruleset_list:
                ruleset_list.append(ruleset_details_dict)
            continue

        ruleset_details_dict["RulesetName"] = ruleset
        ruleset_details_dict["MultiValue"] = False
        ruleset_list.append(ruleset_details_dict)

    return ruleset_list

def get_rule_rulesets(rule_name):
    with open('/tmp/' + ORIGINAL_ZIP_RULES_FOLDER + '/' + rule_name + '/' + FILE_NAME_RULE_PARAMETER) as infile:
        parameters = json.load(infile)

    #in case, multi-value
    all_ruleset_categories = []
    return_ruleset = []

    for ruleset in parameters['Parameters']['RuleSets']:
        if DELIMITER_IN_RULESET not in ruleset:
            return_ruleset.append(ruleset)

        if ruleset.split(DELIMITER_IN_RULESET)[0] in all_ruleset_categories:
            continue
        all_ruleset_categories.append(ruleset.split(DELIMITER_IN_RULESET)[0])

        value_ruleset = []
        for ruleset_second in parameters['Parameters']['RuleSets']:
            if DELIMITER_IN_RULESET not in ruleset_second:
                continue
            if ruleset.split(DELIMITER_IN_RULESET)[0] == ruleset_second.split(DELIMITER_IN_RULESET)[0]:
                value_ruleset.append(ruleset_second.split(DELIMITER_IN_RULESET)[1])
        value_ruleset.sort()
        return_ruleset.append(ruleset.split(DELIMITER_IN_RULESET)[0]+DELIMITER_IN_RULESET+DELIMITER_MULTI.join(value_ruleset))

    return return_ruleset

def add_ruleset_fields(etl_data, ruleset_definition_list, rule_rulesets_list):
    for ruleset in ruleset_definition_list:
        etl_data[ruleset["RulesetName"]] = get_value_for_rule(rule_rulesets_list, ruleset)
    return etl_data

def get_value_for_rule(rule_rulesets_list, ruleset):
    if not ruleset['MultiValue']:
        if ruleset['RulesetName'] not in rule_rulesets_list:
            return 'False'
        return 'True'

    for each_rule_ruleset in rule_rulesets_list:
        try:
            if each_rule_ruleset.split(DELIMITER_IN_RULESET)[0] == ruleset['RulesetName']:
                return each_rule_ruleset.split(DELIMITER_IN_RULESET)[1]
        except:
            # Not splitable, meaning not multivalue
            continue

    # no rule_ruleset matched, meaning not present
    return 'False'

def update_codebuild_param(ruleset_definition_list):
    codebuild_client = boto3.client('codebuild')
    new_deployment_needed = False

    codebuild_template = codebuild_client.batch_get_projects(names=[CODEBUILD_TEMPLATE_NAME])
    env_variables = codebuild_template['projects'][0]['environment']['environmentVariables']

    env_variables_new_list = []
    current_value = {}
    for env_var in env_variables:
        if env_var['name'] == 'DATALAKE_QUERIES_BOOL':
            if env_var['value'] == 'false':
                return False
        if env_var['name'] in ['FIREHOSE_KEY_LIST', 'ATHENA_COLUMN_LIST']:
            current_value[env_var['name']] = env_var['value']
            continue
        env_variables_new_list.append(env_var)

    commun_col = [
        'ConfigRuleArn',
        'EngineRecordedTime',
        'ConfigRuleName',
        'ResourceType',
        'ResourceId',
        'ResultRecordedTime',
        'ConfigRuleInvokedTime',
        'AccountId',
        'AwsRegion',
        'Annotation',
        'ComplianceType',
        'WhitelistedComplianceType']

    all_col = []
    all_col += commun_col
    for ruleset_definition in ruleset_definition_list:
        all_col.append(ruleset_definition['RulesetName'])
    new_value_firehose_key = ','.join(all_col)

    if current_value['FIREHOSE_KEY_LIST'] != new_value_firehose_key:
        new_deployment_needed = True

    key_list_env = {
        'name': 'FIREHOSE_KEY_LIST',
        'value': new_value_firehose_key
        }
    env_variables_new_list.append(key_list_env)

    athena_env_value_list = []
    for col in all_col:
        athena_env_value_list.append("`" + col.lower() + "` string")
    new_value_athena = ','.join(athena_env_value_list)

    if current_value['ATHENA_COLUMN_LIST'] != new_value_athena:
        new_deployment_needed = True

    athena_env = {
        'name': 'ATHENA_COLUMN_LIST',
        'value': new_value_athena
        }
    env_variables_new_list.append(athena_env)

    if new_deployment_needed:
        env = {
            'type': codebuild_template['projects'][0]['environment']['type'],
            'image': codebuild_template['projects'][0]['environment']['image'],
            'computeType': codebuild_template['projects'][0]['environment']['computeType'],
            'environmentVariables': env_variables_new_list
            }
        codebuild_client.update_project(name=CODEBUILD_TEMPLATE_NAME, environment=env)
        return True

    return False

def lambda_handler(event, context):
    compliance_account_id = context.invoked_function_arn.split(":")[4]
    compliance_account_region = context.invoked_function_arn.split(":")[3]
    artifact_bucket = "-".join([BUCKET_PREFIX, compliance_account_id, compliance_account_region])
    ruleset_bucket = "-".join([BUCKET_PREFIX_RULESET_TXT, compliance_account_id, compliance_account_region])

    download_rules_parameters_locally(artifact_bucket)

    ruleset_definition_list = []
    ruleset_definition_list = get_ruleset_definition(ruleset_bucket)
    if update_codebuild_param(ruleset_definition_list):
        try:
            codepipeline_client = boto3.client('codepipeline')
            codepipeline_client.start_pipeline_execution(name=CODEPIPELINE_NAME)
        except Exception as e:
            print('Error not able to trigger the codepipeline: ' + str(e))

    output = []
    for record in event['records']:
        payload = base64.b64decode(record['data'])
        payload_data = json.loads(payload.decode("utf-8"))
        etl_data = {
            "ConfigRuleArn": payload_data['ConfigRuleArn'],
            "EngineRecordedTime": payload_data['EngineRecordedTime'],
            "ConfigRuleName": payload_data["ConfigRuleName"],
            "ResourceType": payload_data['ResourceType'],
            "ResourceId": payload_data['ResourceId'],
            "ComplianceType": payload_data['ComplianceType'],
            "ResultRecordedTime": payload_data['ResultRecordedTime'],
            "ConfigRuleInvokedTime": payload_data['ConfigRuleInvokedTime'],
            "AccountId": payload_data['AccountId'],
            "AwsRegion": payload_data['AwsRegion'],
            "Annotation": payload_data['Annotation']
            }
        if is_compliance_result_whitelisted(etl_data):
            del etl_data['ComplianceType']
            etl_data['ComplianceType'] = 'COMPLIANT'
            etl_data["WhitelistedComplianceType"] = 'True'
        else:
            etl_data["WhitelistedComplianceType"] = 'False'

        rule_rulesets_list = get_rule_rulesets(etl_data["ConfigRuleName"])
        etl_data = add_ruleset_fields(etl_data, ruleset_definition_list, rule_rulesets_list)
        data_to_return = json.dumps(etl_data) + '\n'
        output_record = {
            'recordId': record['recordId'],
            'result': 'Ok',
            'data': base64.b64encode(data_to_return.encode('utf-8')).decode("utf-8")
            }
        output.append(output_record)
    return {'records': output}
