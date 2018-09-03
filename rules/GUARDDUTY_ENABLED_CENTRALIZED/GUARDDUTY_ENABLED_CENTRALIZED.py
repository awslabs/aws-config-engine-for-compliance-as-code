##################################################################################################
#    Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the 'License'). You may not use this
#    file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
#    or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
#    the specific language governing permissions and limitations under the License.
###################################################################################################

'''
#####################################
##           Gherkin               ##
#####################################

Rule Name:
	GUARDUTY_ENABLED_CENTRALIZED

Description:
	Check whether Amazon GuardDuty is enabled, and optionally if it is centralized in an specific AWS Account.

Trigger:
    Periodic

Resource Type to report on:
    AWS::::Account

Rule Parameters:
        | -------------------------| --------- | ------------------------------------ | ------------------------- |
        | Parameter Name           | Type      | Description                          | Notes                     |
        | ------------------------ | --------- | ------------------------------------ | ------------------------- |
        | CentralMonitoringAccount | Optional  | AWS Account where GuardDuty should   | must be a 12-digit string |
        |                          |           | be centralized.                      |                           |
        | ------------------------ | --------- | ------------------------------------ | ------------------------- |


Feature:
	In order to: have visibility on potential threat in my network
	         As: a Security Officer
	     I want: to ensure that GuardDuty is enabled
                 and optionally centralized in a specific AWS Account.

Scenarios:
  Scenario 1:
   Given: The CentralMonitoringAccount parameter is configured
    And: the CentralMonitoringAccount parameter is not a 12-digit string
   Then: Return an error

  Scenario 2:
   Given: GuardDuty do not have any Detector configured
   Then: Return NON_COMPLIANT

  Scenario 3:
   Given: GuardDuty has at least one Detector configured
    And: No detector is enabled
   Then: Return NON_COMPLIANT

  Scenario 4:
   Given: GuardDuty has at least one Detector configured
    And: At least one detector is enabled
    And: the CentralMonitoringAccount parameter is not configured
   Then: Return COMPLIANT

  Scenario 5:
   Given: GuardDuty has at least one Detector configured
    And: At least one detector is enabled
    And: the CentralMonitoringAccount parameter is configured and valid
    And: the CentralMonitoringAccount parameter is equal to the AwsAccountId in the lambda invoking_event
   Then: Return COMPLIANT with an annotation mentioning that it is the centralized account.

  Scenario 6:
   Given: GuardDuty has at least one Detector configured
    And: At least one detector is enabled
    And: the CentralMonitoringAccount parameter is configured and valid
    And: No MasterID configuration associated to the enabled detector(s) exists
   Then: Return NON_COMPLIANT

  Scenario 7:
   Given: GuardDuty has at least one Detector configured
    And: At least one detector is enabled
    And: the CentralMonitoringAccount parameter is configured and valid
    And: At least one MasterID configuration associated to the enabled detector(s) exists
    And: No MasterID configuration associated to the enabled detector(s) matches the CentralMonitoringAccount parameter
   Then: Return NON_COMPLIANT with annotation on no MasterID configured

  Scenario 8:
   Given: GuardDuty has at least one Detector configured
    And: At least one detector is enabled
    And: the CentralMonitoringAccount parameter is configured and valid
    And: At least one MasterID configuration associated to the enabled detector(s) exists
    And: At least one MasterID configuration associated to the enabled detector(s) matches the CentralMonitoringAccount parameter
   Then: Return COMPLIANT

'''

import json
import re
import logging
import boto3
import botocore
from botocore.exceptions import ClientError
# import liblogging

STS_CLIENT = boto3.client('sts')
LOGGER = logging.getLogger()

EVAL_RESOURCE_TYPE = 'AWS::::Account'

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters'])

    # liblogging.logEvent(event)

    central_monitoring_account = None
    if 'CentralMonitoringAccount' in rule_parameters:
        if re.match('^[0-9]{12}$', rule_parameters['CentralMonitoringAccount']):
            central_monitoring_account = rule_parameters['CentralMonitoringAccount']
        else:
            return build_error_response('Customer error while parsing input parameters',
                                        'CentralMonitoringAccount',
                                        'InvalidParameterValueException',
                                        'Parameter \'CentralMonitoringAccount\' is not a valid AWS account (12-digit string).'
                                       )

    try:
        if invoking_event['messageType'] == 'ScheduledNotification':
            return evaluate_scheduled_compliance(event, event['executionRoleArn'], central_monitoring_account)
        return {'internalErrorMessage': 'Unexpected message type ' + str(invoking_event)}
    except ClientError as ex:
        if is_internal_error(ex):
            LOGGER.error('Unexpected error while completing API request ' + str(ex))
            return build_internal_error_response('Unexpected error while completing API request', str(ex))
        LOGGER.error('Encountered error while making API request '+ str(ex))
        return build_error_response('Encountered error while making API request',
                                    str(ex),
                                    ex.response['Error']['Code'],
                                    ex.response['Error']['Message']
                                   )

def evaluate_scheduled_compliance(event, role_arn, central_monitoring_account):
    guardduty_client = get_guardduty_client(role_arn)
    detectorIds = guardduty_client.list_detectors()['DetectorIds']

    if not detectorIds:
        return build_evaluation(event, 'NON_COMPLIANT', 'GuardDuty is not configured.')

    detector_enabled = False
    master_exists = False
    is_expected_master = False

    while True:
        for detector in detectorIds:

            if is_detector_enabled(guardduty_client, detector):
                detector_enabled = True

                if not central_monitoring_account:
                    return build_evaluation(event, 'COMPLIANT', 'GuardDuty is enabled.')

                guardduty_master_account = guardduty_client.get_master_account(DetectorId=detector)

                if 'Master' in guardduty_master_account:
                    master_exists = True

                    if central_monitoring_account == guardduty_master_account['Master']['AccountId']:
                        is_expected_master = True

                        if guardduty_master_account['Master']['RelationshipStatus'] == 'Monitored':
                            return build_evaluation(event, 'COMPLIANT', 'GuardDuty is enabled and centralized.')

        if 'NextToken' in detectorIds:
            next_token = detectorIds['NextToken']
            detectorIds = guardduty_client.list_detectors(NextToken=next_token)['DetectorIds']
        else:
            break

    if not detector_enabled:
        return build_evaluation(event, 'NON_COMPLIANT', 'GuardDuty is not enabled.')

    if detector_enabled and not master_exists:
        return build_evaluation(event, 'NON_COMPLIANT', 'GuardDuty is enabled but not centralized.')

    if master_exists and not is_expected_master:
        return build_evaluation(event,
                                'NON_COMPLIANT',
                                'GuardDuty is centralized in another account (' + \
                                str(guardduty_master_account['Master']['AccountId']) + \
                                ') than the account specified as parameter (' + \
                                str(central_monitoring_account) + ').')

    if is_expected_master:
        return build_evaluation(event, 'NON_COMPLIANT', 'GuardDuty has the correct Central account, but it is not in \'Monitored\' state.')

    return build_internal_error_response('Unexpected behavior from the rule ')

def is_detector_enabled(guardduty_client, detector):
    detector_info = guardduty_client.get_detector(DetectorId=detector)
    return detector_info['Status'] == 'ENABLED'

def build_evaluation(event, complianceType, annotation):
    return {
        'ComplianceResourceType': EVAL_RESOURCE_TYPE,
        'ComplianceResourceId': event['accountId'],
        'ComplianceType': complianceType,
        'Annotation': annotation,
        'OrderingTimestamp': str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    }

def get_assume_role_credentials(role_arn):
    try:
        assume_role_response = STS_CLIENT.assume_role(RoleArn=role_arn, RoleSessionName='configLambdaExecution')
        return assume_role_response['Credentials']
    except ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = 'AWS Config does not have permission to assume the IAM role.'
        else:
            ex.response['Error']['Message'] = 'InternalError'
            ex.response['Error']['Code'] = 'InternalError'
        raise ex

def get_guardduty_client(role_arn):
    credentials = get_assume_role_credentials(role_arn)
    return boto3.client('guardduty',
                        aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

def is_internal_error(exception):
    return (not isinstance(exception, botocore.exceptions.ClientError)
            or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code']
            or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internalErrorMessage, internalErrorDetails=None):
    return build_error_response(internalErrorMessage, internalErrorDetails, 'InternalError', 'InternalError')

def build_error_response(internalErrorMessage, internalErrorDetails=None, customerErrorCode=None, customerErrorMessage=None):
    return {
        'internalErrorMessage': internalErrorMessage,
        'internalErrorDetails': internalErrorDetails,
        'customerErrorMessage': customerErrorMessage,
        'customerErrorCode': customerErrorCode
    }
