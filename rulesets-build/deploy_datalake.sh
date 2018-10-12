#!/usr/bin/env bash

centralizedbucketconfig=("$1")
centralizedcomplianceevent=("$2")
keylistfirehose=("$3")
columnkeylist=("$4")
accountlist=("$5")
locationaccountlist=("$6")

aws cloudformation deploy --stack-name Compliance-Engine-Datalake-DO-NOT-DELETE --template-file ./rulesets-build/compliance-account-analytics-setup.yaml --no-fail-on-empty-changeset --parameter-overrides CentralizedS3BucketConfig="${centralizedbucketconfig[@]}" CentralizedS3BucketComplianceEventName="${centralizedcomplianceevent[@]}" KeyListGeneratedByFirehose="${keylistfirehose[@]}" ColumnKeyList="${columnkeylist[@]}" AccountList="${accountlist[@]}" LocationAccountListCSV="${locationaccountlist[@]}"

response=$(aws cloudformation list-change-sets --stack-name Compliance-Engine-Datalake-DO-NOT-DELETE --query "Summaries[*].ChangeSetName" --output text)
declare -a changesets=($response)
for changeset in "${changesets[@]}"; do
  aws cloudformation delete-change-set --change-set-name $changeset --stack-name Compliance-Engine-Datalake-DO-NOT-DELETE
done
