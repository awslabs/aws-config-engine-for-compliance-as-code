#!/usr/bin/env bash

cd rules

INDEX=0

IFS=',' read -r -a array <<< "$3"
for regionname in "${array[@]}"; do 
  echo Deploy in $regionname
  RDKLIB_LAYER_ARN=$(aws lambda list-layer-versions --layer-name $RDKLIB_LAYER_NAME --region $regionname --query 'LayerVersions[0].LayerVersionArn' | tr -d '"')
  echo Using layer $RDKLIB_LAYER_ARN
  if [ -f ../rules_lambda_vpc.json ]; then
    LambdaSubnets=$(cat ../rules_lambda_vpc.json | jq --arg regionname "$regionname" '."AllActiveRegions"[$regionname]."LambdaSubnets"')
    LambdaSecurityGroups=$(cat ../rules_lambda_vpc.json | jq --arg regionname "$regionname" '."AllActiveRegions"[$regionname]."LambdaSecurityGroups"')
    if [ $LambdaSubnets != "null" ] && [ $LambdaSecurityGroups != "null" ]; then
      echo Creating Custom Config Rule Lambda Functions in $LambdaSubnets in $regionname
      echo rdk -r $regionname deploy -f --all --lambda-role-arn $1 --rdklib-layer-arn $RDKLIB_LAYER_ARN --lambda-subnets ${LambdaSubnets//\"} --lambda-security-groups ${LambdaSecurityGroups//\"}
      rdk -r $regionname deploy -f --all --lambda-role-arn $1 --rdklib-layer-arn $RDKLIB_LAYER_ARN --lambda-subnets ${LambdaSubnets//\"} --lambda-security-groups ${LambdaSecurityGroups//\"}
      unset LambdaSubnets LambdaSecurityGroups
    else
      echo Creating Custom Rule Lambda Functions in $regionname
      echo rdk -r $regionname deploy -f --all --lambda-role-arn $1 --rdklib-layer-arn $RDKLIB_LAYER_ARN
      rdk -r $regionname deploy -f --all --lambda-role-arn $1 --rdklib-layer-arn $RDKLIB_LAYER_ARN
    fi
  else
    echo Creating Custom Rule Lambda Functions in $regionname
    echo rdk -r $regionname deploy -f --all --lambda-role-arn $1 --rdklib-layer-arn $RDKLIB_LAYER_ARN
    rdk -r $regionname deploy -f --all --lambda-role-arn $1 --rdklib-layer-arn $RDKLIB_LAYER_ARN
  fi
  funcname=${2//_/}
  if [ $INDEX != 0 ]; then
    aws lambda update-function-configuration --function-name RDK-Rule-Function-$funcname --environment Variables={MainRegion=${array[0]}} --region $regionname
  fi
  let INDEX=${INDEX}+1
done

cd ..
