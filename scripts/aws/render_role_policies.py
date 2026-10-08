#!/usr/bin/env python3
"""Render least-scope policy/trust files for a primary administrator to attach to EXISTING roles."""
import argparse
import json
from pathlib import Path


def render(config):
    region, account, params = config['region'], config['account_id'], config['parameters']
    if 'REPLACE' in json.dumps(config):
        raise ValueError('Replace all example placeholders first')
    prefix = params['Prefix']
    root = f'arn:aws'
    bucket = f'{root}:s3:::{prefix}-logs-{account}-{region}'
    table = f'{root}:dynamodb:{region}:{account}:table/{prefix}-state'
    loggroups = f'{root}:logs:{region}:{account}:log-group:/ec2/security/*'
    lambda_logs = f'{root}:logs:{region}:{account}:log-group:/aws/lambda/{prefix}-*:*'
    def allow(actions, resources, condition=None):
        value = {'Effect': 'Allow', 'Action': actions, 'Resource': resources}
        if condition: value['Condition'] = condition
        return value
    base = [allow(['logs:CreateLogStream','logs:PutLogEvents'], lambda_logs),
            allow('sns:Publish', params['NotificationTopicArn']),
            allow(['s3:PutObject','s3:GetObject','s3:GetObjectVersion','s3:GetObjectRetention'], bucket + '/*'),
            allow(['s3:ListBucket','s3:GetBucketLocation'], bucket),
            allow(['kms:GenerateDataKey','kms:Decrypt'], params['KmsKeyArn']),
            allow(['dynamodb:GetItem'], table),
            allow('sqs:SendMessage', f'{root}:sqs:{region}:{account}:{prefix}-delivery-dlq')]
    def state_write(keys):
        return allow(['dynamodb:PutItem','dynamodb:UpdateItem'], table,
                     {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': keys}})
    roles = {
        'ArchiveRole': base + [state_write(['MONTH#*','INCIDENT#*']),
            allow(['logs:DescribeLogGroups','logs:DescribeExportTasks','logs:DescribeLogStreams'], '*'), allow('logs:CreateExportTask', loggroups)],
        'DetectorRole': base + [state_write(['EVENT#*','AUTH#*','DISK#*','INCIDENT#*']),
            allow(['dynamodb:Query'], table + '/index/open-incidents'),
            allow(['logs:DescribeLogGroups','ec2:DescribeNetworkInterfaces'], '*'),
            allow('kms:DescribeKey', params['KmsKeyArn']),
            allow(['s3:GetBucketObjectLockConfiguration','s3:GetBucketVersioning','s3:GetEncryptionConfiguration'], bucket),
            allow('logs:GetLogEvents', loggroups + ':log-stream:*'),
            allow(['sqs:ReceiveMessage','sqs:DeleteMessage','sqs:GetQueueAttributes'], f'{root}:sqs:{region}:{account}:{prefix}-delivery-dlq')],
        'ResponseRole': base + [state_write(['ISOLATION#*','INCIDENT#*']),
            allow(['guardduty:GetFindings'], f'{root}:guardduty:{region}:{account}:detector/*'),
            allow(['ec2:DescribeInstances','ec2:DescribeNetworkInterfaces','ec2:DescribeSecurityGroups'], '*')],
        'RestoreRole': base + [state_write(['ISOLATION#*','INCIDENT#*']),
            allow(['ec2:DescribeInstances','ec2:DescribeNetworkInterfaces'], '*')],
    }
    enis = config.get('approved_eni_ids', [])
    if not enis:
        raise ValueError('approved_eni_ids must explicitly scope response/restore mutation permissions')
    targets = [f'{root}:ec2:{region}:{account}:network-interface/{eni}' for eni in enis]
    for name in ('ResponseRole','RestoreRole'):
        roles[name].append(allow('ec2:ModifyNetworkInterfaceAttribute', targets))
    roles['FirehoseRole'] = [allow(['s3:AbortMultipartUpload','s3:GetBucketLocation','s3:ListBucket','s3:ListBucketMultipartUploads'], bucket),
        allow(['s3:GetObject','s3:PutObject','s3:AbortMultipartUpload'], [bucket+'/raw/*',bucket+'/errors/*']),
        allow(['kms:GenerateDataKey','kms:Decrypt'], params['KmsKeyArn'])]
    roles['LogsDeliveryRole'] = [allow(['firehose:PutRecord','firehose:PutRecordBatch'], f'{root}:firehose:{region}:{account}:deliverystream/{prefix}-raw')]
    roles['StateMachineRole'] = [allow('lambda:InvokeFunction', [f'{root}:lambda:{region}:{account}:function:{prefix}-{name}' for name in ('monthstart','monthstep','monthfailure')])]
    roles['SchedulerRole'] = [allow('states:StartExecution', f'{root}:states:{region}:{account}:stateMachine:{prefix}-monthly'),
        allow('lambda:InvokeFunction', f'{root}:lambda:{region}:{account}:function:{prefix}-operations'),
        allow('sqs:SendMessage', f'{root}:sqs:{region}:{account}:{prefix}-delivery-dlq')]
    principals = {'FirehoseRole':'firehose.amazonaws.com', 'LogsDeliveryRole':f'logs.{region}.amazonaws.com',
                  'StateMachineRole':'states.amazonaws.com','SchedulerRole':'scheduler.amazonaws.com'}
    result = {}
    for name, statements in roles.items():
        result[name+'.policy.json'] = {'Version':'2012-10-17','Statement':statements}
        trust = {'Effect':'Allow','Principal':{'Service':principals.get(name,'lambda.amazonaws.com')},'Action':'sts:AssumeRole'}
        if name == 'LogsDeliveryRole':
            trust['Condition']={'StringEquals':{'aws:SourceAccount':account},'ArnLike':{'aws:SourceArn':loggroups}}
        if name == 'SchedulerRole':
            trust['Condition']={'StringEquals':{'aws:SourceAccount':account},'ArnLike':{'aws:SourceArn':f'{root}:scheduler:{region}:{account}:schedule/default/{prefix}-*'}}
        result[name+'.trust.json']={'Version':'2012-10-17','Statement':[trust]}
    # Attach to the existing key/topic; they are not changed automatically.
    result['kms-key-policy-fragment.json']={'Sid':'CloudWatchExport', 'Effect':'Allow',
        'Principal':{'Service':f'logs.{region}.amazonaws.com'}, 'Action':['kms:GenerateDataKey','kms:Decrypt'], 'Resource':'*'}
    result['sns-topic-policy-fragment.json']={'Sid':'SecurityAlarmsAndWorkflowFailure', 'Effect':'Allow',
        'Principal':{'Service':['cloudwatch.amazonaws.com','events.amazonaws.com']}, 'Action':'sns:Publish',
        'Resource':params['NotificationTopicArn'], 'Condition':{'StringEquals':{'aws:SourceAccount':account},
        'ArnLike':{'aws:SourceArn':[f'{root}:cloudwatch:{region}:{account}:alarm:*', f'{root}:events:{region}:{account}:rule/{prefix}*']}}}
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=render(json.loads(args.config.read_text()))
    args.output.mkdir(parents=True,exist_ok=False)
    for name,value in result.items():
        (args.output/name).write_text(json.dumps(value,indent=2)+'\n')
    print(args.output)
