import unittest
import sys
from mock import MagicMock, patch, ANY
import botocore

RULE_RESOURCE_TYPE = "AWS::::Account"
RULE_RESOURCE_DEFAULT_VALUE = "account-id"

sts_client_mock = MagicMock()
sts_client_mock.assume_role = MagicMock(return_value={'Credentials':{'AccessKeyId':'access-key', 'SecretAccessKey':'secret', 'SessionToken':'token'}})
config_client_mock = MagicMock()
gd_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'sts':
            return sts_client_mock
        elif client_name == 'config':
            return config_client_mock
        elif client_name == 'guardduty':
            return gd_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()
import GUARDDUTY_ENABLED_CENTRALIZED as rule

class TestUnexpectedNotifications(unittest.TestCase):

    def test_invalid_notification(self):
        response = rule.lambda_handler({'executionRoleArn':'roleArn', 'eventLeftScope': True, 'invokingEvent':'{"messageType":"invalid-type"}', 'ruleParameters':'{}', 'accountId':'account-id', 'configRuleArn':'rule-arn'}, {})
        assert_internal_error_response(self, response)

class TestInvalidCustomerInput(unittest.TestCase):

    def test_CentralMonitoringAccount(self):
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{"CentralMonitoringAccount":"NotAValidString"}'), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_blank_CentralMonitoringAccount(self):
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{"CentralMonitoringAccount":""}'), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    @patch.object(rule, 'evaluate_scheduled_compliance')
    def test_null_CentralMonitoringAccount(self, mock_method):
        rule.lambda_handler(build_lambda_event(), {})
        mock_method.assert_called_once_with(ANY, ANY, None)

    @patch.object(rule, 'evaluate_scheduled_compliance')
    def test_specified_CentralMonitoringAccount(self, mock_method):
        rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        mock_method.assert_called_once_with(ANY, ANY, '112233445566')

class TestScheduledNotification(unittest.TestCase):

    listdetector_empty = {'DetectorIds': []}
    listdetector_valid = {'DetectorIds': ["aaaabbbbccccddddeeeeffff11112222"]}
    listdetector_multiple_valid = {'DetectorIds': ["33334444555566667777888899990000", "aaaabbbbccccddddeeeeffff11112222"]}
    detectorinfo_enabled = {'Status': 'ENABLED'}
    detectorinfo_disabled = {'Status': 'DISABLED'}
    detectorinfo_anyother = {'Status': 'any-other'}
    getmasteraccount_empty = {}
    getmasteraccount_monitored = {'Master': {'AccountId': '112233445566', 'RelationshipStatus': 'Monitored'}}
    getmasteraccount_monitored_wrong = {'Master': {'AccountId': '111122223333', 'RelationshipStatus': 'Monitored'}}
    getmasteraccount_monitored_notmonitored = {'Master': {'AccountId': '112233445566', 'RelationshipStatus': 'Other-status'}}

    def test_sts_unknown_error(self):
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'unknown-code', 'Message':'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event(), {})
        assert_customer_error_response(self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'AccessDenied', 'Message':'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event(), {})
        assert_customer_error_response(self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')

    def test_customer_guardduty_ListDetectors_api_error(self):
        gd_client_mock.list_detectors = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'400', 'Message':'PermissionDenied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event(), {})
        assert_customer_error_response(self, response, '400')

    def test_service_guardduty_ListDetectors_api_error(self):
        gd_client_mock.list_detectors = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'500', 'Message':'service-error'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event(), {})
        assert_customer_error_response(self, response, 'InternalError')

    def test_customer_guardduty_GetDetector_api_error(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'400', 'Message': 'PermissionDenied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event(), {})
        assert_customer_error_response(self, response, '400')

    def test_service_guardduty_GetDetector_api_error(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'500', 'Message': 'service-error'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event(), {})
        assert_customer_error_response(self, response, 'InternalError')

    def test_customer_guardduty_GetMasterAccount_api_error(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        gd_client_mock.get_master_account = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'400', 'Message':'PermissionDenied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        print(response)
        assert_customer_error_response(self, response, '400')

    def test_service_guardduty_GetMasterAccount_api_error(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        gd_client_mock.get_master_account = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'500', 'Message':'service-error'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        assert_customer_error_response(self, response, 'InternalError')

    def test_compliance_NotConfigured(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_empty)
        response = rule.lambda_handler(build_lambda_event(), {})
        resp_expected = build_individual_response('NON_COMPLIANT', 'GuardDuty is not configured.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Configured_NotEnabled(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_disabled)
        response = rule.lambda_handler(build_lambda_event(), {})
        resp_expected = build_individual_response('NON_COMPLIANT', 'GuardDuty is not enabled.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Configured_invalid(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_anyother)
        response = rule.lambda_handler(build_lambda_event(), {})
        resp_expected = build_individual_response('NON_COMPLIANT', 'GuardDuty is not enabled.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Enabled_NotCentralized(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        response = rule.lambda_handler(build_lambda_event(), {})
        resp_expected = build_individual_response('COMPLIANT', 'GuardDuty is enabled.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Enabled_MultipleDetectors_NotCentralized(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_multiple_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        response = rule.lambda_handler(build_lambda_event(), {})
        resp_expected = build_individual_response('COMPLIANT', 'GuardDuty is enabled.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Enabled_CorrectCentralized(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        gd_client_mock.get_master_account = MagicMock(return_value=self.getmasteraccount_monitored)
        response = rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        resp_expected = build_individual_response('COMPLIANT', 'GuardDuty is enabled and centralized.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Enabled_WrongCentralized(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        gd_client_mock.get_master_account = MagicMock(return_value=self.getmasteraccount_monitored_wrong)
        response = rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        resp_expected = build_individual_response('NON_COMPLIANT', 'GuardDuty is centralized in another account (111122223333) than the account specified as parameter (112233445566).')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Enabled_CorrectCentralized_NotMonitored(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        gd_client_mock.get_master_account = MagicMock(return_value=self.getmasteraccount_monitored_notmonitored)
        response = rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        resp_expected = build_individual_response('NON_COMPLIANT', 'GuardDuty has the correct Central account, but it is not in \'Monitored\' state.')
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_Enabled_NotCentralized(self):
        gd_client_mock.list_detectors = MagicMock(return_value=self.listdetector_valid)
        gd_client_mock.get_detector = MagicMock(return_value=self.detectorinfo_enabled)
        gd_client_mock.get_master_account = MagicMock(return_value=self.getmasteraccount_empty)
        response = rule.lambda_handler(build_lambda_event('{\"CentralMonitoringAccount\":\"112233445566\"}'), {})
        resp_expected = build_individual_response('NON_COMPLIANT', 'GuardDuty is enabled but not centralized.')
        assert_successful_evaluation(self, response, resp_expected)

def build_lambda_event(ruleParameters='{}'):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    return {
        'executionRoleArn':'roleArn',
        'eventLeftScope': True,
        'invokingEvent': invoking_event,
        'ruleParameters': ruleParameters,
        'accountId': 'account-id',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan'
        }

def build_individual_response(ComplianceType, Annotation=None, ComplianceResourceType=RULE_RESOURCE_TYPE, ComplianceResourceId=RULE_RESOURCE_DEFAULT_VALUE):
    response = {}
    response['ComplianceType'] = ComplianceType
    response['ComplianceResourceType'] = ComplianceResourceType
    response['ComplianceResourceId'] = ComplianceResourceId
    if Annotation:
        response['Annotation'] = Annotation
    return response

def assert_customer_error_response(testClass, response, customerErrorCode=None, customerErrorMessage=None):
    if customerErrorCode:
        testClass.assertEqual(customerErrorCode, response['customerErrorCode'])
    if customerErrorMessage:
        testClass.assertEqual(customerErrorMessage, response['customerErrorMessage'])
    testClass.assertTrue(response['customerErrorCode'])
    testClass.assertTrue(response['customerErrorMessage'])
    testClass.assertTrue(response['internalErrorMessage'])
    testClass.assertTrue(response['internalErrorDetails'])

def assert_internal_error_response(testClass, response):
    testClass.assertFalse('customerErrorCode' in response)
    testClass.assertFalse('customerErrorMessage' in response)
    testClass.assertTrue(response['internalErrorMessage'])

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if "Annotation" in resp_expected:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for r in range(len(resp_expected)):
            testClass.assertEquals(resp_expected[r]['ComplianceType'], response[r]['ComplianceType'])
            testClass.assertEquals(resp_expected[r]['ComplianceResourceType'], response[r]['ComplianceResourceType'])
            testClass.assertEquals(resp_expected[r]['ComplianceResourceId'], response[r]['ComplianceResourceId'])
            testClass.assertTrue(response[r]['OrderingTimestamp'])
            if "Annotation" in resp_expected[r]:
                testClass.assertEquals(resp_expected[r]['Annotation'], response[r]['Annotation'])
