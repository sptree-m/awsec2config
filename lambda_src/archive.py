"""Checkpointed monthly export. Step Functions waits outside Lambda executions."""
import datetime as dt
import gzip
import hashlib
import html
import os
import uuid
import json
import common as c


def save(job):
    condition = 'job_id=:id'
    values = {':id': job['job_id']}
    if job.get('lease_owner'):
        condition += ' AND lease_owner=:owner'
        values[':owner'] = job['lease_owner']
    c.table().put_item(Item=job, ConditionExpression=condition, ExpressionAttributeValues=values)


def start(event, context):
    at = event.get('scheduled_time', c.now().isoformat())
    start_time, end_time = c.previous_month(at)
    revision = event.get('revision', 'initial')
    if revision not in ('initial', 'correction'):
        raise ValueError('Unknown revision')
    month = start_time.strftime('%Y-%m')
    pk = f'MONTH#{month}'
    previous = c.table().get_item(Key={'pk': pk}, ConsistentRead=True).get('Item')
    if previous:
        if previous['revision'] == revision and previous['status'] != 'FAILED':
            return c.reply(previous, 'DONE' if previous['status'] == 'COMPLETE' else 'WAIT')
        if previous['status'] not in ('COMPLETE', 'FAILED'):
            return {'phase': 'WAIT_START', 'request': event}
        if revision == 'initial' and previous['status'] == 'COMPLETE':
            return c.reply(previous, 'DONE')
    groups = json.loads(os.environ['LOG_GROUPS'])
    hours = int(os.environ.get('EXPORT_WINDOW_HOURS', '24'))
    if hours not in (6, 12, 24) or not isinstance(groups, list) or not 1 <= len(groups) <= 8 or len(set(groups)) != len(groups):
        raise ValueError('Require 1–8 unique log groups and 6/12/24-hour export windows')
    chunks = []
    for group in groups:
        matched = []
        paginator = c.client('logs').get_paginator('describe_log_groups')
        for page in paginator.paginate(logGroupNamePrefix=group):
            matched.extend(g for g in page['logGroups'] if g['logGroupName'] == group)
        if len(matched) != 1 or matched[0].get('retentionInDays', 0) < 400:
            raise ValueError('Missing log group or retention below 400 days: ' + group)
        creation = matched[0]['creationTime']
        day = start_time
        while day < end_time:
            end = min(day + dt.timedelta(hours=hours), end_time)
            begin_ms, end_ms = int(day.timestamp() * 1000), int(end.timestamp() * 1000)
            # Do not silently treat a group created mid-month as full-month coverage.
            if end_ms > creation:
                chunks.append({'group': group, 'from': max(begin_ms, creation), 'to_exclusive': end_ms,
                               'created_mid_month': creation > int(start_time.timestamp() * 1000)})
            day = end
    if not chunks:
        raise ValueError('No applicable export windows; month coverage is unknown')
    job = {'pk': pk, 'job_id': uuid.uuid4().hex, 'revision': revision, 'month': month,
           'status': 'RUNNING', 'started_at': c.now().isoformat(), 'start': start_time.isoformat(),
           'end': end_time.isoformat(), 'chunks': chunks, 'index': 0, 'objects': 0, 'compressed_bytes': 0,
           'warnings': [], 'ttl': int(c.now().timestamp()) + 450 * 86400}
    job['prefix'] = f'monthly/account={os.environ["ACCOUNT_ID"]}/region={os.environ["AWS_REGION"]}/month={month}/run={job["job_id"]}'
    if any(x['created_mid_month'] for x in chunks):
        job['warnings'].append('Log groups created mid-month: earlier events are not available')
    job['warnings'].append('Export verification proves artifact integrity, not absence of missing source events')
    # Preserve previous run results in S3 before replacing the month pointer.
    if previous:
        c.evidence('reports/month-history', previous)
        condition = 'job_id=:old AND (#s=:complete OR #s=:failed)'
        c.table().put_item(Item=job, ConditionExpression=condition,
                           ExpressionAttributeNames={'#s': 'status'},
                           ExpressionAttributeValues={':old': previous['job_id'], ':complete': 'COMPLETE', ':failed': 'FAILED'})
    else:
        try:
            c.table().put_item(Item=job, ConditionExpression='attribute_not_exists(pk)')
        except Exception as exc:
            if not c.conditional(exc):
                raise
            return {'phase': 'WAIT_START', 'request': event}
    return c.reply(job)


def put_json(key, value):
    return c.client('s3').put_object(Bucket=os.environ['ARCHIVE_BUCKET'], Key=key, Body=c.dumps(value).encode(),
                                   ChecksumAlgorithm='SHA256', ContentType='application/json', ServerSideEncryption='aws:kms',
                                   SSEKMSKeyId=os.environ['KMS_KEY_ARN'])


def find_task(name):
    token = None
    while True:
        args = {'limit': 50}
        if token:
            args['nextToken'] = token
        page = c.client('logs').describe_export_tasks(**args)
        for task in page['exportTasks']:
            if task.get('taskName') == name:
                return task
        token = page.get('nextToken')
        if not token:
            return None


class HashReader:
    def __init__(self, body):
        self.body, self.sha, self.size = body, hashlib.sha256(), 0
    def read(self, size=-1):
        data = self.body.read(size)
        self.sha.update(data)
        self.size += len(data)
        return data


def verify_object(key, context):
    s3 = c.client('s3')
    bucket = os.environ['ARCHIVE_BUCKET']
    head = s3.head_object(Bucket=bucket, Key=key)
    if not head.get('VersionId') or head.get('ServerSideEncryption') != 'aws:kms' or head.get('SSEKMSKeyId') != os.environ['KMS_KEY_ARN'] or head['ContentLength'] <= 0:
        raise ValueError('Archive versioning/encryption not verified')
    retained = head.get('ObjectLockRetainUntilDate')
    if head.get('ObjectLockMode') != 'COMPLIANCE' or not retained or retained < head['LastModified'] + dt.timedelta(days=400, seconds=-5):
        raise ValueError('Archive object retention below 400 days')
    if head['ContentLength'] > 512 * 1024 * 1024:
        raise ValueError('Export object exceeds 512MiB: reduce the export time window and restart')
    fetched = s3.get_object(Bucket=bucket, Key=key, VersionId=head['VersionId'])
    reader = HashReader(fetched['Body'])
    expanded = 0
    try:
        with gzip.GzipFile(fileobj=reader) as stream:
            while True:
                data = stream.read(1024 * 1024)
                if not data:
                    break
                expanded += len(data)
                if expanded > 2 * 1024 ** 3 or context.get_remaining_time_in_millis() < 15000:
                    raise ValueError('Export verification limit reached: reduce chunk size')
        if reader.size != head['ContentLength']:
            raise ValueError('Compressed length mismatch')
    finally:
        fetched['Body'].close()
    return {'key': key, 'version_id': head['VersionId'], 'sha256': reader.sha.hexdigest(),
            'compressed_bytes': reader.size, 'expanded_bytes': expanded,
            'retain_until': retained, 'kms_key_id': head.get('SSEKMSKeyId')}


def step(event, context):
    job = c.table().get_item(Key={'pk': event['pk']}, ConsistentRead=True)['Item']
    if job['job_id'] != event['job_id']:
        raise ValueError('Another monthly run owns this record')
    if job['status'] == 'COMPLETE':
        return c.reply(job, 'DONE')
    if job['status'] == 'FAILED':
        raise ValueError('Monthly run failed; restart explicitly with recovery command')
    lease = uuid.uuid4().hex
    epoch = int(c.now().timestamp())
    try:
        c.table().update_item(Key={'pk': job['pk']},
            UpdateExpression='SET lease_owner=:owner, lease_until=:until',
            ConditionExpression='job_id=:id AND (attribute_not_exists(lease_until) OR lease_until<:now)',
            ExpressionAttributeValues={':owner': lease, ':until': epoch + 360, ':now': epoch, ':id': job['job_id']})
    except Exception as exc:
        if c.conditional(exc):
            return c.reply(job)
        raise
    job['lease_owner'], job['lease_until'] = lease, epoch + 360
    try:
        return advance(job, context)
    finally:
        c.table().update_item(Key={'pk': job['pk']}, UpdateExpression='REMOVE lease_owner, lease_until',
                             ConditionExpression='lease_owner=:owner', ExpressionAttributeValues={':owner': lease})


def advance(job, context):
    if job['index'] == len(job['chunks']):
        manifest = {k: v for k, v in job.items() if k not in ('chunks', 'lease_owner', 'lease_until')}
        manifest.update({'status': 'COMPLETE', 'completed_at': c.now().isoformat(),
                         'object_manifests_prefix': job['prefix'] + '/verification/',
                         'source_completeness': 'REQUIRES_HEARTBEAT_AND_RAW_RECONCILIATION'})
        put_json(job['prefix'] + '/manifest.json', manifest)
        rows = ''.join(f'<li>{html.escape(w)}</li>' for w in job['warnings'])
        page = '<!doctype html><meta charset="utf-8"><h1>Monthly archive ' + html.escape(job['month']) + '</h1><p>Verified gzip objects: ' + str(job['objects']) + '</p><ul>' + rows + '</ul>'
        c.client('s3').put_object(Bucket=os.environ['ARCHIVE_BUCKET'], Key=job['prefix'] + '/report.html',
            Body=page.encode(), ChecksumAlgorithm='SHA256', ContentType='text/html; charset=utf-8', ServerSideEncryption='aws:kms', SSEKMSKeyId=os.environ['KMS_KEY_ARN'])
        job['status'] = 'COMPLETE'
        save(job)
        c.notify(c.incident_id('monthly-complete', job['job_id']), 'P3', 'Monthly compressed export complete; review coverage warnings',
                 {'manifest': job['prefix'] + '/manifest.json'})
        return c.reply(job, 'DONE')
    chunk = job['chunks'][int(job['index'])]
    name = f'awsec2-{job["job_id"]}-{job["index"]}'
    destination = f'{job["prefix"]}/exports/chunk={job["index"]}'
    if not job.get('task_id'):
        # Reconcile an API-success/checkpoint-failure before creating another export.
        found = find_task(name)
        if found:
            expected = {'logGroupName': chunk['group'], 'from': int(chunk['from']), 'to': int(chunk['to_exclusive']) - 1,
                        'destination': os.environ['ARCHIVE_BUCKET'], 'destinationPrefix': destination}
            if any(found.get(k) != v for k, v in expected.items()):
                raise ValueError('Recovered export task does not match this window/destination')
            job['task_id'] = found['taskId']
            save(job)
            return c.reply(job)
        try:
            result = c.client('logs').create_export_task(**{'taskName': name, 'logGroupName': chunk['group'],
                'from': int(chunk['from']), 'to': int(chunk['to_exclusive']) - 1,
                'destination': os.environ['ARCHIVE_BUCKET'], 'destinationPrefix': destination})
        except Exception as exc:
            if c.error_code(exc) in ('LimitExceededException', 'OperationAbortedException', 'ServiceUnavailableException'):
                return c.reply(job)
            else:
                raise
        job['task_id'] = result['taskId']
        save(job)
        return c.reply(job)
    task = c.client('logs').describe_export_tasks(taskId=job['task_id'])['exportTasks'][0]
    status = task['status']['code']
    if status in ('PENDING', 'RUNNING', 'PENDING_CANCEL'):
        return c.reply(job)
    if status != 'COMPLETED':
        raise ValueError('Export task failed: ' + status)
    args = {'Bucket': os.environ['ARCHIVE_BUCKET'], 'Prefix': destination + '/'}
    if job.get('last_key'):
        args['StartAfter'] = job['last_key']
    args['MaxKeys'] = 1
    page = c.client('s3').list_objects_v2(**args)
    objects = page.get('Contents', [])
    if objects:
        item = objects[0]
        proof = verify_object(item['Key'], context)
        put_json(job['prefix'] + '/verification/' + hashlib.sha256(item['Key'].encode()).hexdigest() + '.json',
                 {'chunk': chunk, 'task_id': job['task_id'], **proof})
        job['objects'] += 1
        job['chunk_objects'] = job.get('chunk_objects', 0) + 1
        job['compressed_bytes'] += proof['compressed_bytes']
        job['last_key'] = item['Key']
        save(job)
        return c.reply(job, 'NEXT')
    if not job.get('chunk_objects'):
        job['warnings'].append(f'No exported objects for chunk {job["index"]}: verify source coverage')
        c.notify(c.incident_id('empty-export', name), 'P2', 'Monthly export window has no files; coverage unknown', chunk)
    put_json(job['prefix'] + f'/chunks/{job["index"]}.json', {'window': chunk, 'task_id': job['task_id'], 'objects': job.get('chunk_objects', 0)})
    job['index'] += 1
    for field in ('task_id', 'last_key', 'chunk_objects'):
        job.pop(field, None)
    save(job)
    return c.reply(job, 'NEXT')


def failure(event, context):
    details = {'error': event.get('failure', {}), 'request_id': context.aws_request_id}
    if event.get('pk'):
        job = c.table().get_item(Key={'pk': event['pk']}, ConsistentRead=True).get('Item')
        if job and job['job_id'] == event.get('job_id'):
            job['status'] = 'FAILED'
            job['failure_evidence'] = c.evidence('reports/month-failure', details)
            save(job)
            details['job_id'] = job['job_id']
    c.notify(c.incident_id('monthly-failure', event.get('job_id', context.aws_request_id)), 'P2', 'Monthly export FAILED or BLOCKED', details)
    return {'phase': 'FAILED'}
