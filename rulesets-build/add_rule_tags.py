import botocore

def tag_config_rule(rule_name, cfn_tags, my_session):
    try:
        config_client=my_session.client('config')
    except:
        print("Cannot establish remote session connection. Please review assumeRole permissions and iam policies.")
        raise
    try:
        config_arn=config_client.describe_config_rules(ConfigRuleNames=[rule_name])['ConfigRules'][0]['ConfigRuleArn']
        print(config_arn)
        response = config_client.tag_resource(
            ResourceArn=config_arn,
            Tags=cfn_tags
        )
    except:
        print("rules name [{}] not found.".format(rule_name))
        return False
    return True

def execute_add_rule_tags_script(template_bucket_name, remote_account_id, default_rule_tags_script_suffix, remote_session, s3_client):
    try:
        add_tag_script_name=remote_account_id + default_rule_tags_script_suffix
        add_tag_script = s3_client.get_object(Bucket=template_bucket_name, Key=add_tag_script_name)
        for line in add_tag_script['Body'].iter_lines():
            line_to_string=str(line)
            cfn_tags=[]
            if "--config-rule-names" in line_to_string:
                try:
                    config_rule_name=line_to_string.split("--config-rule-names ",1)[1].split(" ")[0]
                    tags=line_to_string.split("--tags ",1)[1].split(" ")[0:-2]
                    for tag in tags:
                        tag_dict={}
                        tag_dict['Key']=tag.split(",")[0].replace("Key=", "")
                        tag_dict['Value']=tag.split(",")[1].replace("Value=", "")
                        cfn_tags.append(tag_dict)
                except:
                    print("ERROR: The script is malformed. Please regenerate.")
                    raise
                response=tag_config_rule(config_rule_name,cfn_tags,remote_session)
                if response:
                    print("Adding following tags to {} in account {}".format(config_rule_name, remote_account_id))
                    print(cfn_tags)
    except botocore.exceptions.ClientError as e:
        #pass if there is no script for rules tagging
        if e.response['Error']['Code'] == 'AccessDenied':
            print("Access Denial to {}".format(template_bucket_name))
            raise e
