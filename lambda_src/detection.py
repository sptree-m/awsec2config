"""Normalize OS events, notify on tampering, and correlate authentication failures."""
import base64
import gzip
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
import common as c


def parse(message):
    if message.lstrip().startswith('<'):
        root = ET.fromstring(message)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        eid = int(root.findtext('e:System/e:EventID', namespaces=ns))
        fields = {x.attrib.get('Name'): x.text or '' for x in root.findall('e:EventData/e:Data', ns)}
        return {'event_id': eid, 'source': fields.get('IpAddress', ''), 'user': fields.get('TargetUserName', ''),
                'kind': 'failure' if eid == 4625 else 'success' if eid == 4624 else 'change'}
    try:
        record = json.loads(message)
        if record.get('type') == 'heartbeat':
            return {'kind': 'heartbeat', 'record': record}
    except (ValueError, AttributeError):
        pass
    failed = re.search(r'Failed \S+ for (?:invalid user )?(\S+) from (\S+)', message)
    succeeded = re.search(r'Accepted \S+ for (\S+) from (\S+)', message)
    if failed or succeeded:
        match = failed or succeeded
        return {'kind': 'failure' if failed else 'success', 'user': match[1], 'source': match[2]}
    if 'awsec2_identity' in message or 'awsec2_privilege' in message or 'awsec2_remote' in message:
        return {'kind': 'audit_change'}
    return {'kind': 'other'}


def handler(event, context):
    packed = base64.b64decode(event['awslogs']['data'])
    if len(packed) > 6 * 1024 * 1024:
        raise ValueError('Subscription batch too large')
    # Bound decompression; reject an oversized payload instead of silently dropping it.
    import io
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError('Decompressed batch too large')
    batch = json.loads(raw)
    if batch.get('messageType') == 'CONTROL_MESSAGE':
        return {'status': 'CONTROL'}
    if batch.get('owner') != os.environ['ACCOUNT_ID']:
        raise ValueError('Unexpected subscription account')
    group, instance = batch['logGroup'], batch['logStream']
    if group not in json.loads(os.environ['LOG_GROUPS']) or not re.fullmatch(r'i-[0-9a-f]{8,17}', instance):
        raise ValueError('Unexpected source group/instance stream')
    processed = 0
    for item in batch.get('logEvents', []):
        seen = 'EVENT#' + hashlib.sha256((group + instance + item['id']).encode()).hexdigest()
        receipt = c.table().get_item(Key={'pk': seen}, ConsistentRead=True).get('Item')
        if receipt and receipt.get('done'):
            continue
        age = int(c.now().timestamp() * 1000) - item['timestamp']
        if age < -120000 or age > 1800000:
            # Old records remain archived but must not be counted as a new live attack.
            continue
        try:
            normalized = parse(item['message'])
        except (ValueError, ET.ParseError, TypeError):
            c.notify(c.incident_id('parse', seen), 'P2', 'Security event parse failure; raw logs remain archived',
                     {'group': group, 'instance': instance, 'event_id': item['id']})
            normalized = {'kind': 'unparsed'}
        eid = normalized.get('event_id')
        if eid in (1102, 4719, 4720, 4726, 4728, 4732, 4756):
            c.notify(c.incident_id('os-change', seen), 'P1', 'Audit/account change: investigate; OS event alone does not authorize isolation',
                     {'instance': instance, 'event_id': eid, 'group': group})
        elif normalized['kind'] == 'audit_change':
            c.notify(c.incident_id('audit-change', seen), 'P2', 'Ubuntu identity/privilege/SSH configuration changed', {'instance': instance})
        if normalized['kind'] in ('failure', 'success') and normalized.get('source') and normalized.get('user'):
            key = hashlib.sha256((instance + normalized['source'] + normalized['user']).encode()).hexdigest()
            slot = item['timestamp'] // 300000
            pk = f'AUTH#{key}#{slot}'
            if normalized['kind'] == 'failure':
                # A transaction makes a duplicate log delivery unable to inflate the counter.
                # DynamoDB low-level transaction uses explicit attribute values.
                if not receipt or not receipt.get('counted'):
                    try:
                        c.client('dynamodb').transact_write_items(TransactItems=[
                            {'Put': {'TableName': os.environ['STATE_TABLE'], 'Item': {'pk': {'S': seen}, 'counted': {'BOOL': True}, 'done': {'BOOL': False},
                                      'ttl': {'N': str(int(c.now().timestamp()) + 172800)}}, 'ConditionExpression': 'attribute_not_exists(pk)'}},
                            {'Update': {'TableName': os.environ['STATE_TABLE'], 'Key': {'pk': {'S': pk}},
                                        'UpdateExpression': 'SET #ttl=:t ADD failures :one',
                                        'ExpressionAttributeNames': {'#ttl': 'ttl'},
                                        'ExpressionAttributeValues': {':t': {'N': str(int(c.now().timestamp()) + 3600)}, ':one': {'N': '1'}}}}
                        ])
                    except Exception as exc:
                        if c.error_code(exc) == 'TransactionCanceledException':
                            existing = c.table().get_item(Key={'pk': seen}, ConsistentRead=True).get('Item')
                            if not existing or not existing.get('counted'):
                                raise
                        else:
                            raise
                count = c.table().get_item(Key={'pk': pk}, ConsistentRead=True)['Item']['failures']
                if count >= 10:
                    c.notify(c.incident_id('auth-burst', pk), 'P2', 'At least 10 authentication failures in a five-minute bucket',
                             {'instance': instance, 'source': normalized['source'], 'user': normalized['user']})
            else:
                failures = sum(c.table().get_item(Key={'pk': f'AUTH#{key}#{s}'}, ConsistentRead=True).get('Item', {}).get('failures', 0)
                               for s in (slot, slot - 1, slot - 2))
                if failures >= 10:
                    c.notify(c.incident_id('success-after-failure', seen), 'P2', 'Successful authentication after repeated failures',
                             {'instance': instance, 'source': normalized['source'], 'user': normalized['user']})
        # Notification checkpoints are deterministic IDs; retries do not lose a pending SNS message.
        c.table().put_item(Item={'pk': seen, 'done': True, 'ttl': int(c.now().timestamp()) + 172800})
        processed += 1
    return {'processed': processed}


def aws_change(event, context):
    """Trusted CloudTrail management changes notify only, never directly isolate EC2."""
    if event.get('account') != os.environ['ACCOUNT_ID'] or event.get('detail-type') != 'AWS API Call via CloudTrail':
        raise ValueError('Unexpected management event')
    detail=event['detail']; action=detail['eventName']; request=detail.get('requestParameters') or {}
    if detail.get('errorCode'):
        return {'status':'FAILED_API_CALL_NO_CHANGE'}
    priority='P2'
    if action in ('StopLogging','DeleteTrail','DisableKey','ScheduleKeyDeletion'):
        priority='P1'
    elif action in ('DeleteLogGroup','PutRetentionPolicy'):
        if request.get('logGroupName') not in json.loads(os.environ['LOG_GROUPS']):
            return {'status':'UNRELATED'}
        if action=='PutRetentionPolicy' and int(request.get('retentionInDays',0))>=400:
            return {'status':'RETENTION_VALID'}
        priority='P1'
    elif action.startswith('PutBucket') or action=='PutObjectLockConfiguration':
        if request.get('bucketName') != os.environ['ARCHIVE_BUCKET']:
            return {'status':'UNRELATED'}
        priority='P1'
    elif action=='AuthorizeSecurityGroupIngress':
        permissions=request.get('ipPermissions',{})
        items=permissions.get('items',[]) if isinstance(permissions,dict) else permissions
        exposed=False
        for rule in items:
            ranges=rule.get('ipRanges',{})
            ranges=ranges.get('items',[]) if isinstance(ranges,dict) else ranges
            ipv6=rule.get('ipv6Ranges',{})
            ipv6=ipv6.get('items',[]) if isinstance(ipv6,dict) else ipv6
            world=any(r.get('cidrIp')=='0.0.0.0/0' for r in ranges) or any(r.get('cidrIpv6')=='::/0' for r in ipv6)
            ports=rule.get('ipProtocol')=='-1' or rule.get('ipProtocol') in ('tcp','6') and any(int(rule.get('fromPort',65536))<=port<=int(rule.get('toPort',-1)) for port in (22,3389))
            exposed |= world and ports
        if not exposed:
            return {'status':'NO_WORLD_ADMIN_PORT'}
    proof=c.evidence('incidents/aws-changes',event)
    ident=c.incident_id('aws-change',detail.get('eventID') or event['id'])
    c.notify(ident,priority,'AWS security-relevant management change: '+action,proof)
    return {'status':'NOTIFIED','incident_id':ident}
