#!/usr/bin/env bash
# The purpose of this script is to find the Athena named queries created in the CloudFormation stack and execute them in the appropriate order.

CLOUDFORMATION_STACK_NAME="Compliance-Engine-Datalake-DO-NOT-DELETE" # The name of the stack that creates the Athena named queries.
EXECUTION_OUTPUT_LOCATION="s3://aws-athena-query-results-$1-us-east-1/" # The S3 bucket and prefix where the query outputs will be stored.

# These stages must match the LogicalId of the AWS::Athena::NamedQuery resources created by CloudFormation and in the appropriate order of execution.
stages=(
  AthenaNamedQueryInitDB
  AthenaNamedQueryInitTable
  AthenaNamedQueryConfigTable
  AccountListTable
)

# Function to print verbose output for execution status.
# Parameters:
# 1. The current stage
# 2. The name of the named query being executed
# 3. The status of the query
# 4. The query output location
function printVerboseOutput {
  printf "Stage: [$1]; Named Query: [$2]; Status: [$3]; Output: [$4]\n"
}

for stage in ${stages[@]} # Loop through each defined stage
do
  # Get the CloudFormation Stack resources and select the PhysicalResourceId. This is used for finding the named query resources in Athena.
  CF_STACK_RESOURCE_ID=$(aws cloudformation describe-stack-resources --stack-name $CLOUDFORMATION_STACK_NAME --query "StackResources[? ResourceType == 'AWS::Athena::NamedQuery' && LogicalResourceId == '$stage'].PhysicalResourceId" --output text)
  
  # Get the named query Athena resources
  ATHENA_NAMED_QUERY=$(aws athena get-named-query --named-query-id $CF_STACK_RESOURCE_ID)
  NAME=$(echo $ATHENA_NAMED_QUERY | jq -r '.NamedQuery.Name') # Parse the name of the query from the Athena resource
  DATABASE=$(echo $ATHENA_NAMED_QUERY | jq -r '.NamedQuery.Database') # Parse the database name from the Athena resource
  QUERY_STRING=$(echo $ATHENA_NAMED_QUERY | jq -r '.NamedQuery.QueryString') # Parse the Query String from the Athena resource
  
  # Execute the Query using the named query properties and save the return Execution ID
  QUERY_EXECUTION_ID=$(aws athena start-query-execution --query-string "$QUERY_STRING" --query-execution-context "Database=\"$DATABASE\"" --result-configuration "OutputLocation=$EXECUTION_OUTPUT_LOCATION" --query "QueryExecutionId" --output text)

  while $true; do # Continuous loop to wait for the query to finish executing

    # Get the Athena query results using the query execution id. 
    QUERY_EXECUTION_RESULTS=$(aws athena get-query-execution --query-execution-id $QUERY_EXECUTION_ID) 
    QUERY_EXECUTION_STATUS=$(echo $QUERY_EXECUTION_RESULTS | jq -r '.QueryExecution.Status.State') # Parse the state
    QUERY_OUTPUT_LOCATION=$(echo $QUERY_EXECUTION_RESULTS | jq -r '.QueryExecution.ResultConfiguration.OutputLocation') # Parse the query output location

    if [[ $QUERY_EXECUTION_STATUS == "SUCCEEDED" ]]; then # If the query is successful return output and continue to the next stage.
      printVerboseOutput $stage "$NAME" $QUERY_EXECUTION_STATUS $QUERY_OUTPUT_LOCATION
      break
    fi

    if [[ $QUERY_EXECUTION_STATUS == "QUEUED" || $QUERY_EXECUTION_STATUS == "RUNNING" ]]; then # If the query is queued or running sleep for 3 seconds and look back.
      printVerboseOutput $stage "$NAME" $QUERY_EXECUTION_STATUS $QUERY_OUTPUT_LOCATION
      sleep 3
      continue
    fi
    
    if [[ $QUERY_EXECUTION_STATUS == "CANCELLED" ]]; then
      printVerboseOutput $stage "$NAME" $QUERY_EXECUTION_STATUS $QUERY_OUTPUT_LOCATION # Send verbose output and exit.
      printf "Query cancelled. Unable to proceed.\n"
      exit 0
    fi

    # The query is in FAILED state. Parse reason out of the Athena query execution results, and print verbose output and error message.
    QUERY_STATE_CHANGE_REASON=$(echo $QUERY_EXECUTION_RESULTS | jq -r '.QueryExecution.Status.StateChangeReason')
    printVerboseOutput $stage "$NAME" $QUERY_EXECUTION_STATUS $QUERY_OUTPUT_LOCATION 
    printf "Error during execution: [$QUERY_STATE_CHANGE_REASON]. Unable to proceed.\n" 
    exit 1 # Exit with non-zero code.
  done
done 
