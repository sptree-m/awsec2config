"""Five-minute delivery/retention/isolation checks and unacknowledged P1 escalation."""
import datetime as dt
import json
import os
import common as c


def alarm(key, priority, summary, details=None, bucket_minutes=15):
    slot = int(c.now().timestamp()) // (bucket_minutes * 60)
    c.notify(c.incident_id(key, str(slot)), priority, summary, details)


def handler(event, context):
    if os.environ.get('DELIVERY_DLQ_URL'):
        sqs = c.client('sqs')
        messages = sqs.receive_message(QueueUrl=os.environ['DELIVERY_DLQ_URL'], MaxNumberOfMessages=10, VisibilityTimeout=300).get('Messages', [])
        for message in messages:
            proof = c.evidence('incidents/delivery-failures', {'message_id': message['MessageId'], 'body': message['Body']})
            c.notify(c.incident_id('dlq', message['MessageId']), 'P1', 'Security task failed after retries; archived for recovery', proof)
            sqs.delete_message(QueueUrl=os.environ['DELIVERY_DLQ_URL'], ReceiptHandle=message['ReceiptHandle'])
    inventory = json.loads(os.environ['INSTANCE_IDS'])
    if len(inventory) > 50:
        raise ValueError('Split health monitoring across stacks for more than 50 instances')
    logs = c.client('logs')
    for ident in inventory:
        try:
            page = logs.get_log_events(logGroupName='/ec2/security/heartbeat', logStreamName=ident,
                                       startTime=int((c.now() - dt.timedelta(minutes=15)).timestamp() * 1000),
                                       endTime=int(c.now().timestamp() * 1000), startFromHead=False, limit=1)
            events = page.get('events', [])
            if not events:
                alarm('heartbeat-' + ident, 'P2', 'No heartbeat in 15 minutes', {'instance': ident})
            else:
                beat = json.loads(events[-1]['message'])
                if beat.get('type') != 'heartbeat':
                    raise ValueError('Heartbeat format mismatch')
                if beat.get('audit_disabled'):
                    alarm('audit-disabled-' + ident, 'P1', 'OS auditing disabled or verification unavailable', {'instance': ident})
                if beat.get('audit_lost', 0) != 0 or beat.get('service_failures'):
                    alarm('health-' + ident, 'P2', 'Audit loss or stopped monitoring service', {'instance': ident, 'health': beat})
                if beat.get('disk_free_percent', 100) < 10:
                    # Require consecutive observations covering 10 minutes.
                    pk = 'DISK#' + ident
                    prior = c.table().get_item(Key={'pk': pk}).get('Item')
                    epoch = int(c.now().timestamp())
                    if not prior or epoch - prior.get('last_epoch', 0) > 600:
                        prior = {'pk': pk, 'first_epoch': epoch}
                    prior.update({'last_epoch': epoch, 'ttl': epoch + 1800})
                    c.table().put_item(Item=prior)
                    if epoch - prior['first_epoch'] >= 600:
                        alarm('disk-' + ident, 'P2', 'Disk space below 10% for 10 minutes', {'instance': ident})
                else:
                    c.table().update_item(Key={'pk': 'DISK#' + ident}, UpdateExpression='SET first_epoch=:t, last_epoch=:t, #ttl=:ttl',
                                         ExpressionAttributeNames={'#ttl': 'ttl'},
                                         ExpressionAttributeValues={':t': int(c.now().timestamp()), ':ttl': int(c.now().timestamp()) + 1800})
        except Exception as exc:
            alarm('heartbeat-read-' + ident, 'P2', 'Heartbeat verification UNKNOWN', {'instance': ident, 'error': c.error_code(exc)})
        state = c.table().get_item(Key={'pk': 'ISOLATION#' + ident}, ConsistentRead=True).get('Item')
        if state:
            if state['status'] in ('PARTIAL', 'RESTORING') or (state['status'] == 'ISOLATING' and (c.now() - c.timestamp(state['started_at'])).total_seconds() > 300):
                alarm('isolation-pending-' + ident, 'P1', 'Isolation/restore incomplete; manual recovery required', {'instance': ident, 'status': state['status']})
            if state['status'] == 'ISOLATED':
                try:
                    observed = c.client('ec2').describe_network_interfaces(NetworkInterfaceIds=[p['eni'] for p in state['plan']])['NetworkInterfaces']
                    actual = {n['NetworkInterfaceId']: sorted(g['GroupId'] for g in n['Groups']) for n in observed}
                    if actual != {p['eni']: p['after'] for p in state['plan']}:
                        alarm('isolation-drift-' + ident, 'P1', 'Isolation ENI security groups changed')
                except Exception as exc:
                    alarm('isolation-unknown-' + ident, 'P1', 'Isolation verification UNKNOWN', {'error': c.error_code(exc)})
    for group in json.loads(os.environ['LOG_GROUPS']):
        try:
            found = []
            for page in logs.get_paginator('describe_log_groups').paginate(logGroupNamePrefix=group):
                found.extend(g for g in page['logGroups'] if g['logGroupName'] == group)
            if len(found) != 1 or found[0].get('retentionInDays', 0) < 400:
                alarm('retention-' + group, 'P2', 'Log retention below 400 days or missing group', {'group': group})
        except Exception as exc:
            alarm('retention-unknown-' + group, 'P2', 'Retention verification UNKNOWN', {'error': c.error_code(exc)})
    try:
        s3 = c.client('s3')
        bucket = os.environ['ARCHIVE_BUCKET']
        lock = s3.get_object_lock_configuration(Bucket=bucket)['ObjectLockConfiguration']
        retention = lock.get('Rule', {}).get('DefaultRetention', {})
        if lock.get('ObjectLockEnabled') != 'Enabled' or retention.get('Mode') != 'COMPLIANCE' or retention.get('Days', 0) < 400:
            alarm('archive-lock', 'P2', 'Archive default retention below 400 days')
        if s3.get_bucket_versioning(Bucket=bucket).get('Status') != 'Enabled':
            alarm('archive-versioning', 'P2', 'Archive versioning not enabled')
        encryption = s3.get_bucket_encryption(Bucket=bucket)['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
        if encryption.get('SSEAlgorithm') != 'aws:kms' or encryption.get('KMSMasterKeyID') != os.environ['KMS_KEY_ARN']:
            alarm('archive-encryption', 'P2', 'Archive encryption differs from configured KMS key')
    except Exception as exc:
        alarm('archive-unknown', 'P2', 'Archive protection verification UNKNOWN', {'error': c.error_code(exc)})
    try:
        state = c.client('kms').describe_key(KeyId=os.environ['KMS_KEY_ARN'])['KeyMetadata']['KeyState']
        if state != 'Enabled':
            alarm('kms-key-state', 'P1', 'Archive KMS key is disabled or scheduled for deletion', {'state': state})
    except Exception as exc:
        alarm('kms-unknown', 'P2', 'KMS key verification UNKNOWN', {'error': c.error_code(exc)})
    local = c.now().astimezone(c.JST)
    month = c.previous_month(c.now().isoformat())[0].strftime('%Y-%m')
    archive = c.table().get_item(Key={'pk': 'MONTH#' + month}, ConsistentRead=True).get('Item')
    if (local.day > 3 or local.day == 3 and local.hour >= 18) and (not archive or archive['revision'] == 'initial' and archive['status'] != 'COMPLETE'):
        alarm('monthly-deadline-' + month, 'P2', 'Monthly export overdue or missing')
    response = c.table().query(IndexName='open-incidents', KeyConditionExpression='incident_status=:s',
                               ExpressionAttributeValues={':s': 'OPEN'})
    while True:
        for incident in response.get('Items', []):
            age = int(c.now().timestamp()) - incident['created_epoch']
            if age >= 900:
                level = 'ESCALATION' if age >= 1800 else 'REMINDER'
                # Publish directly: reminders must not create recursively escalating incidents.
                c.client('sns').publish(TopicArn=os.environ['NOTIFICATION_TOPIC'],
                    Subject=f'EC2 security P1 {level}',
                    Message=c.dumps({'incident_id': incident['incident_id'], 'age_minutes': int(age // 60),
                                     'summary': incident['summary'], 'evidence': incident['evidence']}))
        if not response.get('LastEvaluatedKey'):
            break
        response = c.table().query(IndexName='open-incidents', KeyConditionExpression='incident_status=:s',
                                   ExpressionAttributeValues={':s': 'OPEN'}, ExclusiveStartKey=response['LastEvaluatedKey'])
    return {'status': 'CHECKED'}
