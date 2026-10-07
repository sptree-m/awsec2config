"""Shared AWS runtime. No credentials or SDK clients are created at import time."""
import datetime as dt
import functools
import hashlib
import json
import os
import uuid
from decimal import Decimal

UTC = dt.timezone.utc
JST = dt.timezone(dt.timedelta(hours=9))

@functools.lru_cache()
def client(service):
    import boto3
    return boto3.client(service)

@functools.lru_cache()
def table():
    import boto3
    return boto3.resource('dynamodb').Table(os.environ['STATE_TABLE'])

def now():
    return dt.datetime.now(UTC)

def timestamp(value):
    if isinstance(value, dt.datetime):
        return value.astimezone(UTC)
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(UTC)

def dumps(value):
    def default(item):
        if isinstance(item, dt.datetime):
            return item.astimezone(UTC).isoformat()
        if isinstance(item, Decimal):
            return int(item) if item == int(item) else str(item)
        raise TypeError(type(item).__name__)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=default)

def error_code(exc):
    return getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)

def conditional(exc):
    return error_code(exc) == 'ConditionalCheckFailedException'

def evidence(prefix, value):
    key = f'{prefix}/{now():%Y/%m/%d}/{uuid.uuid4().hex}.json'
    result = client('s3').put_object(Bucket=os.environ['ARCHIVE_BUCKET'], Key=key,
                                   Body=dumps(value).encode(), ChecksumAlgorithm='SHA256', ContentType='application/json',
                                   ServerSideEncryption='aws:kms', SSEKMSKeyId=os.environ['KMS_KEY_ARN'])
    return {'key': key, 'version_id': result.get('VersionId')}

def incident_id(source, identifier):
    return hashlib.sha256(f'{source}:{identifier}'.encode()).hexdigest()[:32]

def notify(identifier, priority, summary, details=None):
    """At-least-once SNS delivery; state is retryable if publication fails."""
    pk = 'INCIDENT#' + identifier
    existing = table().get_item(Key={'pk': pk}, ConsistentRead=True).get('Item')
    if existing and existing.get('message_id'):
        return existing
    if not existing:
        record = {'pk': pk, 'incident_id': identifier, 'priority': priority,
                  'summary': summary, 'created_at': now().isoformat(), 'created_epoch': int(now().timestamp()),
                  'incident_status': 'OPEN' if priority == 'P1' else 'NOTICE',
                  'ttl': int(now().timestamp()) + 450 * 86400}
        record['evidence'] = evidence('incidents/notifications', {'record': record, 'details': details or {}})
        try:
            table().put_item(Item=record, ConditionExpression='attribute_not_exists(pk)')
            existing = record
        except Exception as exc:
            if not conditional(exc):
                raise
            existing = table().get_item(Key={'pk': pk}, ConsistentRead=True)['Item']
    message = {'incident_id': identifier, 'priority': priority, 'summary': summary,
               'evidence': existing['evidence'], 'account': os.environ['ACCOUNT_ID'],
               'region': os.environ['AWS_REGION']}
    published = client('sns').publish(TopicArn=os.environ['NOTIFICATION_TOPIC'],
                                     Subject=f'EC2 security {priority}: {identifier}', Message=dumps(message))
    table().update_item(Key={'pk': pk}, UpdateExpression='SET message_id=:m',
                        ExpressionAttributeValues={':m': published['MessageId']})
    return {**existing, 'message_id': published['MessageId']}

def previous_month(at):
    end = timestamp(at).astimezone(JST).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start = (end - dt.timedelta(days=1)).replace(day=1)
    return start, end

def reply(job, phase='WAIT'):
    return {'phase': phase, 'pk': job['pk'], 'job_id': job['job_id']}
