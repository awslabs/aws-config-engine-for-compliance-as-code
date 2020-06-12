#!/usr/bin/env bash

DEFAULT_RULE_TAGS_SCRIPT_SUFFIX="_rule_tags.sh"
OTHER_REGIONS=$1
if [ "$OTHER_REGIONS" != "none" ]; then
  cat account_list.json | jq -r '.AllAccounts[] | ([.AccountID , .Region, (.Tags | join(","))] | join(" "))' > wellformedlist.txt

  cd rules
  while IFS=' ' read -ra line; do
    account_id="${line[0]}"
    template_file_name="${account_id}.json"
    rule_tag_script_name="${account_id}${DEFAULT_RULE_TAGS_SCRIPT_SUFFIX}"
    IFS=',' read -r -a array <<< ${line[1]}
    rulesets="${line[2]}"
    regionname="${array[@]}"
    echo Generate in $regionname for $account_id
    rdk create-rule-template --rulesets ${rulesets} --output-file ${template_file_name} --tag-config-rules-script ${rule_tag_script_name} --rules-only
    aws s3 cp ${template_file_name} s3://$3-$regionname/${template_file_name}
    aws s3 cp ${rule_tag_script_name} s3://$3-$regionname/${rule_tag_script_name}
  done < ../wellformedlist.txt
else
  cat account_list.json | jq -r '.AllAccounts[] | ([.AccountID , (.Tags | join(","))] | join(" "))' > wellformedlist.txt

  cd rules
  while IFS=' ' read -ra line; do
    account_id="${line[0]}"
    template_file_name="${account_id}.json"
    rule_tag_script_name="${account_id}${DEFAULT_RULE_TAGS_SCRIPT_SUFFIX}"
    rulesets="${line[1]}"
    rdk create-rule-template --rulesets ${rulesets} --output-file ${template_file_name} --tag-config-rules-script ${rule_tag_script_name} --rules-only
    aws s3 cp ${template_file_name} s3://$2/${template_file_name}
    aws s3 cp ${rule_tag_script_name} s3://$2/${rule_tag_script_name}

  done < ../wellformedlist.txt

fi
