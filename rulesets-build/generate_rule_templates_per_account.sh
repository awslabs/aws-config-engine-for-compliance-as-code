#!/usr/bin/env bash

cat account_list.json | jq -r '.AllAccounts[] | ([.AccountID , (.Tags | join(","))] | join(" "))' > wellformedlist.txt

cd rules
while IFS=' ' read -ra line; do
  account_id="${line[0]}"
  template_file_name="${account_id}.json"
  rulesets="${line[1]}"
  rdk create-rule-template --rulesets ${rulesets} --output-file ${template_file_name} --rules-only
  aws s3 cp ${template_file_name} s3://$1/${template_file_name}

done < ../wellformedlist.txt
