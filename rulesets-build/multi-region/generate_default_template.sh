#!/usr/bin/env bash

cd rules
rdk create-rule-template --rulesets $2 --output-file otherregionsdefault.json --rules-only
IFS=',' read -r -a array <<< $1
for regionname in "${array[@]}"; do 
  echo Generate in $regionname
  aws s3 cp otherregionsdefault.json s3://$3-$regionname/default.json
done
cd ..
