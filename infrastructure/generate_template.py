#!/usr/bin/env python3
"""Generate the checked-in CloudFormation JSON without third-party build dependencies."""
import json
from pathlib import Path


def ref(name): return {'Ref': name}
def att(name, field='Arn'): return {'Fn::GetAtt': [name, field]}
def sub(text): return {'Fn::Sub': text}

PARAMETERS = {
    'Prefix': {'Type': 'String', 'Default': 'awsec2config', 'AllowedPattern': '[a-z][a-z0-9-]{2,24}'},
    'CodeBucket': {'Type': 'String', 'Description': 'Existing same-region private bucket containing the release Lambda ZIP'},
    'CodeKey': {'Type': 'String', 'Description': 'Versioned release lambda.zip key; use a new key for each release'},
    'KmsKeyArn': {'Type': 'String', 'AllowedPattern': 'arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+'},
    'NotificationTopicArn': {'Type': 'String', 'Description': 'Existing SNS topic with confirmed primary/deputy subscribers'},
    'ArchiveRoleArn': {'Type': 'String'}, 'DetectorRoleArn': {'Type': 'String'},
    'ResponseRoleArn': {'Type': 'String'}, 'RestoreRoleArn': {'Type': 'String'},
    'LogsDeliveryRoleArn': {'Type': 'String'}, 'FirehoseRoleArn': {'Type': 'String'},
    'StateMachineRoleArn': {'Type': 'String'}, 'SchedulerRoleArn': {'Type': 'String'},
    'InstanceIds': {'Type': 'String', 'Description': 'JSON array of monitored instance IDs, at most 50'},
    'IsolationGroups': {'Type': 'String', 'Description': 'JSON map of VPC ID to pre-created approved isolation SG'},
    'EndpointGroupIds': {'Type': 'String', 'Description': 'JSON array of approved private SSM/Logs interface endpoint SG IDs'},
    'ActiveLogGroups': {'Type': 'String', 'Default': '["/ec2/security/windows/security","/ec2/security/windows/system","/ec2/security/windows/powershell","/ec2/security/windows/firewall","/ec2/security/ubuntu/auth","/ec2/security/ubuntu/audit","/ec2/security/heartbeat"]', 'Description': 'JSON array of actually deployed source groups; remove unused OS groups'},
    'ExportWindowHours': {'Type': 'Number', 'Default': 24, 'AllowedValues': [6, 12, 24]},
    'FindingTypes': {'Type': 'String', 'Description': 'Required comma-separated primary-admin approved GuardDuty EC2 finding types'},
}
GROUPS = {'WSecurity': '/ec2/security/windows/security', 'WSystem': '/ec2/security/windows/system',
          'WPowerShell': '/ec2/security/windows/powershell', 'WFirewall': '/ec2/security/windows/firewall',
          'UAuth': '/ec2/security/ubuntu/auth', 'UAudit': '/ec2/security/ubuntu/audit',
          'Heartbeat': '/ec2/security/heartbeat'}
resources = {}
def resource(name, kind, properties, retain=False, **extra):
    resources[name] = {'Type': kind, 'Properties': properties, **extra}
    if retain:
        resources[name].update({'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain'})

resource('ArchiveBucket', 'AWS::S3::Bucket', {
    'BucketName': sub('${Prefix}-logs-${AWS::AccountId}-${AWS::Region}'),
    'VersioningConfiguration': {'Status': 'Enabled'}, 'ObjectLockEnabled': True,
    'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 400}}},
    'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'BlockPublicPolicy': True, 'IgnorePublicAcls': True, 'RestrictPublicBuckets': True},
    'OwnershipControls': {'Rules': [{'ObjectOwnership': 'BucketOwnerEnforced'}]},
    'BucketEncryption': {'ServerSideEncryptionConfiguration': [{'ServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': ref('KmsKeyArn')}, 'BucketKeyEnabled': True}]},
    'LifecycleConfiguration': {'Rules': [{'Id': 'RetainAtLeast400Days', 'Status': 'Enabled',
        'Transitions': [{'TransitionInDays': 90, 'StorageClass': 'GLACIER'}], 'ExpirationInDays': 450,
        'NoncurrentVersionTransitions': [{'TransitionInDays': 90, 'StorageClass': 'GLACIER'}],
        'NoncurrentVersionExpiration': {'NoncurrentDays': 450}}]},
}, True)
resource('ArchiveBucketPolicy', 'AWS::S3::BucketPolicy', {'Bucket': ref('ArchiveBucket'), 'PolicyDocument': {
    'Version': '2012-10-17', 'Statement': [
        {'Sid': 'DenyInsecureTransport', 'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*',
         'Resource': [att('ArchiveBucket'), sub('${ArchiveBucket.Arn}/*')], 'Condition': {'Bool': {'aws:SecureTransport': 'false'}}},
        {'Sid': 'LogsBucketAcl', 'Effect': 'Allow', 'Principal': {'Service': sub('logs.${AWS::Region}.amazonaws.com')},
         'Action': 's3:GetBucketAcl', 'Resource': att('ArchiveBucket'), 'Condition': {'StringEquals': {'aws:SourceAccount': ref('AWS::AccountId')},
             'ArnLike': {'aws:SourceArn': sub('arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/ec2/security/*')}}},
        {'Sid': 'LogsExportWrite', 'Effect': 'Allow', 'Principal': {'Service': sub('logs.${AWS::Region}.amazonaws.com')},
         'Action': 's3:PutObject', 'Resource': sub('${ArchiveBucket.Arn}/monthly/*'), 'Condition': {'StringEquals': {'aws:SourceAccount': ref('AWS::AccountId'), 's3:x-amz-acl': 'bucket-owner-full-control'},
             'ArnLike': {'aws:SourceArn': sub('arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/ec2/security/*')}}},
        {'Sid': 'PreventRuntimeDeletionAndLockOverride', 'Effect': 'Deny', 'Principal': '*',
         'Action': ['s3:DeleteObject', 's3:DeleteObjectVersion', 's3:PutObjectRetention', 's3:BypassGovernanceRetention'],
         'Resource': sub('${ArchiveBucket.Arn}/*'), 'Condition': {'ArnEquals': {'aws:PrincipalArn': [ref('ArchiveRoleArn'), ref('DetectorRoleArn'), ref('ResponseRoleArn'), ref('RestoreRoleArn'), ref('FirehoseRoleArn')]}}}
    ]}}, True)
resource('StateTable', 'AWS::DynamoDB::Table', {'TableName': sub('${Prefix}-state'), 'BillingMode': 'PAY_PER_REQUEST',
    'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'incident_status', 'AttributeType': 'S'}, {'AttributeName': 'created_epoch', 'AttributeType': 'N'}],
    'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
    'GlobalSecondaryIndexes': [{'IndexName': 'open-incidents', 'KeySchema': [{'AttributeName': 'incident_status', 'KeyType': 'HASH'}, {'AttributeName': 'created_epoch', 'KeyType': 'RANGE'}], 'Projection': {'ProjectionType': 'ALL'}}],
    'TimeToLiveSpecification': {'AttributeName': 'ttl', 'Enabled': True},
    'PointInTimeRecoverySpecification': {'PointInTimeRecoveryEnabled': True}, 'SSESpecification': {'SSEEnabled': True}}, True)
for name, group in GROUPS.items():
    resource(name + 'LogGroup', 'AWS::Logs::LogGroup', {'LogGroupName': group, 'RetentionInDays': 400}, True)
resource('RawDelivery', 'AWS::KinesisFirehose::DeliveryStream', {'DeliveryStreamName': sub('${Prefix}-raw'),
    'DeliveryStreamType': 'DirectPut', 'ExtendedS3DestinationConfiguration': {'BucketARN': att('ArchiveBucket'),
        'RoleARN': ref('FirehoseRoleArn'), 'Prefix': 'raw/!{timestamp:yyyy/MM/dd/HH}/',
        'ErrorOutputPrefix': 'errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd}/',
        'CompressionFormat': 'UNCOMPRESSED', 'FileExtension': '.gz',
        'BufferingHints': {'IntervalInSeconds': 60, 'SizeInMBs': 5},
        'EncryptionConfiguration': {'KMSEncryptionConfig': {'AWSKMSKeyARN': ref('KmsKeyArn')}}}}, True)
ENV = {'ARCHIVE_BUCKET': ref('ArchiveBucket'), 'KMS_KEY_ARN': ref('KmsKeyArn'), 'STATE_TABLE': ref('StateTable'),
       'NOTIFICATION_TOPIC': ref('NotificationTopicArn'), 'ACCOUNT_ID': ref('AWS::AccountId'),
       'EXPORT_WINDOW_HOURS': ref('ExportWindowHours'), 'LOG_GROUPS': ref('ActiveLogGroups'), 'INSTANCE_IDS': ref('InstanceIds'),
       'ISOLATION_GROUPS': ref('IsolationGroups'), 'ENDPOINT_GROUP_IDS': ref('EndpointGroupIds'), 'FINDING_TYPES': ref('FindingTypes'), 'DELIVERY_DLQ_URL': ref('DeliveryDlq')}
FUNCTIONS = {'MonthStart': ('archive.start', 'ArchiveRoleArn'), 'MonthStep': ('archive.step', 'ArchiveRoleArn'),
             'MonthFailure': ('archive.failure', 'ArchiveRoleArn'), 'Detector': ('detection.handler', 'DetectorRoleArn'), 'AWSChanges': ('detection.aws_change', 'DetectorRoleArn'),
             'Response': ('response.handler', 'ResponseRoleArn'), 'Resume': ('response.resume', 'ResponseRoleArn'), 'Restore': ('response.restore', 'RestoreRoleArn'),
             'Operations': ('operations.handler', 'DetectorRoleArn')}
for name, (handler, role) in FUNCTIONS.items():
    resource(name + 'RuntimeLog', 'AWS::Logs::LogGroup', {'LogGroupName': sub('${Prefix}-lambda-' + name.lower())}, True)
    # Lambda writes into the explicit 400-day /aws/lambda log group below.
    resources[name + 'RuntimeLog']['Properties'] = {'LogGroupName': sub('/aws/lambda/${Prefix}-' + name.lower()), 'RetentionInDays': 400}
    resource(name, 'AWS::Lambda::Function', {'FunctionName': sub('${Prefix}-' + name.lower()), 'Runtime': 'python3.12',
        'Handler': handler, 'Role': ref(role), 'Timeout': 300, 'MemorySize': 1024,
        'Code': {'S3Bucket': ref('CodeBucket'), 'S3Key': ref('CodeKey')},
        'Environment': {'Variables': {**ENV, 'FUNCTION_PURPOSE': 'restore' if name == 'Restore' else 'operations'}}},
        DependsOn=[name + 'RuntimeLog'])
    resource(name + 'ErrorAlarm', 'AWS::CloudWatch::Alarm', {'AlarmDescription': name + ' failed; check security operations',
        'Namespace': 'AWS/Lambda', 'MetricName': 'Errors', 'Dimensions': [{'Name': 'FunctionName', 'Value': ref(name)}],
        'Statistic': 'Sum', 'Period': 300, 'EvaluationPeriods': 1, 'Threshold': 1,
        'ComparisonOperator': 'GreaterThanOrEqualToThreshold', 'TreatMissingData': 'notBreaching',
        'AlarmActions': [ref('NotificationTopicArn')]})
resource('DetectorPermission', 'AWS::Lambda::Permission', {'Action': 'lambda:InvokeFunction', 'FunctionName': ref('Detector'),
    'Principal': sub('logs.${AWS::Region}.amazonaws.com'), 'SourceAccount': ref('AWS::AccountId'),
    'SourceArn': sub('arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/ec2/security/*')})
for name in GROUPS:
    resource(name + 'RawSubscription', 'AWS::Logs::SubscriptionFilter', {'LogGroupName': ref(name + 'LogGroup'),
        'FilterPattern': '', 'DestinationArn': att('RawDelivery'), 'RoleArn': ref('LogsDeliveryRoleArn')})
    if name != 'Heartbeat':
        resource(name + 'DetectionSubscription', 'AWS::Logs::SubscriptionFilter', {'LogGroupName': ref(name + 'LogGroup'),
            'FilterPattern': '', 'DestinationArn': att('Detector')}, DependsOn=['DetectorPermission'])
    resource(name + 'DeliveryErrorAlarm', 'AWS::CloudWatch::Alarm', {'Namespace': 'AWS/Logs', 'MetricName': 'DeliveryErrors',
        'Dimensions': [{'Name': 'LogGroupName', 'Value': ref(name + 'LogGroup')}], 'Statistic': 'Sum', 'Period': 300,
        'EvaluationPeriods': 1, 'Threshold': 1, 'ComparisonOperator': 'GreaterThanOrEqualToThreshold',
        'TreatMissingData': 'notBreaching', 'AlarmActions': [ref('NotificationTopicArn')]})
resource('RawFreshnessAlarm', 'AWS::CloudWatch::Alarm', {'Namespace': 'AWS/Firehose', 'MetricName': 'DeliveryToS3.DataFreshness',
    'Dimensions': [{'Name': 'DeliveryStreamName', 'Value': ref('RawDelivery')}], 'Statistic': 'Maximum', 'Period': 300,
    'EvaluationPeriods': 1, 'Threshold': 900, 'ComparisonOperator': 'GreaterThanThreshold',
    'TreatMissingData': 'notBreaching', 'AlarmActions': [ref('NotificationTopicArn')]})
catch = [{'ErrorEquals': ['States.ALL'], 'ResultPath': '$.failure', 'Next': 'RecordFailure'}]
retry = [{'ErrorEquals': ['Lambda.ServiceException', 'Lambda.AWSLambdaException', 'Lambda.SdkClientException'], 'IntervalSeconds': 10, 'MaxAttempts': 3, 'BackoffRate': 2}]
states = {'Initialize': {'Type': 'Task', 'Resource': att('MonthStart'), 'Next': 'StartChoice', 'Catch': catch, 'Retry': retry},
          'StartChoice': {'Type': 'Choice', 'Choices': [{'Variable': '$.phase', 'StringEquals': 'WAIT_START', 'Next': 'WaitStart'}, {'Variable': '$.phase', 'StringEquals': 'DONE', 'Next': 'Complete'}], 'Default': 'Advance'},
          'WaitStart': {'Type': 'Wait', 'Seconds': 60, 'Next': 'Reinitialize'},
          'Reinitialize': {'Type': 'Task', 'InputPath': '$.request', 'Resource': att('MonthStart'), 'Next': 'StartChoice', 'Catch': catch, 'Retry': retry},
          'Advance': {'Type': 'Task', 'Resource': att('MonthStep'), 'Next': 'StepChoice', 'Catch': catch, 'Retry': retry},
          'StepChoice': {'Type': 'Choice', 'Choices': [{'Variable': '$.phase', 'StringEquals': 'DONE', 'Next': 'Complete'}, {'Variable': '$.phase', 'StringEquals': 'NEXT', 'Next': 'Advance'}], 'Default': 'Wait'},
          'Wait': {'Type': 'Wait', 'Seconds': 60, 'Next': 'Advance'},
          'RecordFailure': {'Type': 'Task', 'Resource': att('MonthFailure'), 'Next': 'Failed'},
          'Failed': {'Type': 'Fail', 'Error': 'MonthlyExportFailed'}, 'Complete': {'Type': 'Succeed'}}
resource('MonthlyWorkflow', 'AWS::StepFunctions::StateMachine', {'StateMachineName': sub('${Prefix}-monthly'), 'StateMachineType': 'STANDARD',
    'RoleArn': ref('StateMachineRoleArn'), 'Definition': {'StartAt': 'Initialize', 'TimeoutSeconds': 172800, 'States': states}})
for name, day, revision in [('Initial', 1, 'initial'), ('Correction', 4, 'correction')]:
    resource(name + 'MonthlySchedule', 'AWS::Scheduler::Schedule', {'Name': sub('${Prefix}-monthly-' + revision),
        'ScheduleExpression': f'cron(0 18 {day} * ? *)', 'ScheduleExpressionTimezone': 'Asia/Tokyo',
        'FlexibleTimeWindow': {'Mode': 'OFF'}, 'Target': {'Arn': att('MonthlyWorkflow'), 'RoleArn': ref('SchedulerRoleArn'),
            'Input': json.dumps({'revision': revision, 'scheduled_time': '<aws.scheduler.scheduled-time>'}),
            'DeadLetterConfig': {'Arn': att('DeliveryDlq')}, 'RetryPolicy': {'MaximumRetryAttempts': 5, 'MaximumEventAgeInSeconds': 86400}}})
resource('OperationsSchedule', 'AWS::Scheduler::Schedule', {'Name': sub('${Prefix}-operations'), 'ScheduleExpression': 'rate(5 minutes)',
    'FlexibleTimeWindow': {'Mode': 'OFF'}, 'Target': {'Arn': att('Operations'), 'RoleArn': ref('SchedulerRoleArn'),
        'Input': '{}', 'DeadLetterConfig': {'Arn': att('DeliveryDlq')}, 'RetryPolicy': {'MaximumRetryAttempts': 2, 'MaximumEventAgeInSeconds': 600}}})
resource('DeliveryDlq', 'AWS::SQS::Queue', {'QueueName': sub('${Prefix}-delivery-dlq'), 'MessageRetentionPeriod': 1209600, 'SqsManagedSseEnabled': True}, True)
resource('DlqAlarm', 'AWS::CloudWatch::Alarm', {'Namespace': 'AWS/SQS', 'MetricName': 'ApproximateNumberOfMessagesVisible', 'Dimensions': [{'Name': 'QueueName', 'Value': att('DeliveryDlq','QueueName')}], 'Statistic': 'Maximum', 'Period': 60, 'EvaluationPeriods': 1, 'Threshold': 1, 'ComparisonOperator': 'GreaterThanOrEqualToThreshold', 'TreatMissingData': 'notBreaching', 'AlarmActions': [ref('NotificationTopicArn')]})
resource('GuardDutyRule', 'AWS::Events::Rule', {'Name': sub('${Prefix}-guardduty'),
    'EventPattern': {'source': ['aws.guardduty'], 'detail-type': ['GuardDuty Finding'], 'account': [ref('AWS::AccountId')]},
    'Targets': [{'Id': 'CriticalResponse', 'Arn': att('Response'), 'DeadLetterConfig': {'Arn': att('DeliveryDlq')}}]})
for function in ('Response', 'Detector', 'AWSChanges'):
    resource(function + 'AsyncFailure', 'AWS::Lambda::EventInvokeConfig', {'FunctionName': ref(function), 'Qualifier': '$LATEST', 'MaximumEventAgeInSeconds': 600, 'MaximumRetryAttempts': 2, 'DestinationConfig': {'OnFailure': {'Destination': att('DeliveryDlq')}}})
resource('DlqPolicy', 'AWS::SQS::QueuePolicy', {'Queues': [ref('DeliveryDlq')], 'PolicyDocument': {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'events.amazonaws.com'},'Action':'sqs:SendMessage','Resource':att('DeliveryDlq'),'Condition':{'ArnEquals':{'aws:SourceArn':[att('GuardDutyRule'),att('AWSChangeRule')]}}}]}})
resource('AWSChangeRule', 'AWS::Events::Rule', {'Name': sub('${Prefix}-aws-changes'), 'EventPattern': {'source': ['aws.cloudtrail','aws.kms','aws.logs','aws.s3','aws.ec2'], 'detail-type': ['AWS API Call via CloudTrail'], 'account': [ref('AWS::AccountId')], 'detail': {'eventName': ['StopLogging','DeleteTrail','UpdateTrail','DisableKey','ScheduleKeyDeletion','DeleteLogGroup','PutRetentionPolicy','PutBucketVersioning','PutObjectLockConfiguration','PutBucketLifecycle','PutBucketLifecycleConfiguration','AuthorizeSecurityGroupIngress']}}, 'Targets': [{'Id':'NotifyChanges','Arn':att('AWSChanges'),'DeadLetterConfig':{'Arn':att('DeliveryDlq')}}]})
resource('AWSChangesPermission', 'AWS::Lambda::Permission', {'Action':'lambda:InvokeFunction','FunctionName':ref('AWSChanges'),'Principal':'events.amazonaws.com','SourceArn':att('AWSChangeRule')})
resource('GuardDutyPermission', 'AWS::Lambda::Permission', {'Action': 'lambda:InvokeFunction', 'FunctionName': ref('Response'),
    'Principal': 'events.amazonaws.com', 'SourceArn': att('GuardDutyRule')})
resource('WorkflowFailureRule', 'AWS::Events::Rule', {'Name': sub('${Prefix}-workflow-failure'), 'EventPattern': {'source': ['aws.states'],
    'detail-type': ['Step Functions Execution Status Change'], 'detail': {'stateMachineArn': [att('MonthlyWorkflow')], 'status': ['FAILED', 'TIMED_OUT', 'ABORTED']}},
    'Targets': [{'Id': 'NotifyFailure', 'Arn': ref('NotificationTopicArn')}]})
# SNS policies on an existing topic are deliberately managed by its primary administrator.
outputs = {'ArchiveBucket': {'Value': ref('ArchiveBucket')}, 'StateTable': {'Value': ref('StateTable')},
           'MonthlyWorkflowArn': {'Value': att('MonthlyWorkflow')}, 'RestoreFunction': {'Value': ref('Restore')},
           'ResponseFunction': {'Value': ref('Response')}, 'ResumeFunction': {'Value': ref('Resume')}, 'OperationsFunction': {'Value': ref('Operations')}}
template = {'AWSTemplateFormatVersion': '2010-09-09', 'Description': 'EC2 security operations v0.2: retained archives, monthly export, notifications and approved critical isolation; requires existing IAM roles',
            'Parameters': PARAMETERS, 'Resources': resources, 'Outputs': outputs}
if __name__ == '__main__':
    Path(__file__).with_name('security-operations.json').write_text(json.dumps(template, indent=2) + '\n')
