#!/usr/bin/env bash

cd rules

IFS=',' read -r -a array <<< $1
for regionname in "${array[@]}"; do 
  echo Deploy in $regionname
  rdk -r $regionname deploy -f --all
  funcname=${2//_/}
  aws lambda update-function-configuration --function-name RDK-Rule-Function-$funcname --environment Variables={MainRegion=$3} --region $regionname
done

cd ..
