#!/usr/bin/env bash

OTHER_REGIONS=$1
if [ "$OTHER_REGIONS" != "none" ]; then
  cat account_list.json | jq -r '.AllAccounts[] | ([.AccountID , .Region, (.Tags | join(","))] | join(" "))' > wellformedlist.txt

  cd rules
  while IFS=' ' read -ra line; do
    account_id="${line[0]}"
    template_file_name="${account_id}.json"
    IFS=',' read -r -a array <<< ${line[1]}
    rulesets="${line[2]}"
    regionname="${array[@]}"
    echo Generate in $regionname for $account_id
    rdk create-rule-template --rulesets ${rulesets} --output-file ${template_file_name} --rules-only
    aws s3 cp ${template_file_name} s3://$3-$regionname/${template_file_name}
  done < ../wellformedlist.txt
else
  cat account_list.json | jq -r '.AllAccounts[] | ([.AccountID , (.Tags | join(","))] | join(" "))' > wellformedlist.txt

  cd rules
  while IFS=' ' read -ra line; do
    account_id="${line[0]}"
    template_file_name="${account_id}.json"
    rulesets="${line[1]}"
    rdk create-rule-template --rulesets ${rulesets} --output-file ${template_file_name} --rules-only
    aws s3 cp ${template_file_name} s3://$2/${template_file_name}
  
  done < ../wellformedlist.txt

fi
