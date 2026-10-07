"""GuardDuty-backed isolation and a separate, IAM-restricted human restore handler."""
import os
import uuid
import common as c


def configuration():
    import json
    return json.loads(os.environ['ISOLATION_GROUPS'])


def verified_finding(event):
    detail = event['detail']
    if event.get('source') != 'aws.guardduty' or event.get('account') != os.environ['ACCOUNT_ID']:
        raise ValueError('Untrusted finding source/account')
    if event.get('region') != os.environ['AWS_REGION']:
        raise ValueError('Unexpected finding region')
    result = c.client('guardduty').get_findings(DetectorId=detail['service']['detectorId'], FindingIds=[detail['id']])
    findings = result.get('Findings', [])
    if len(findings) != 1:
        raise ValueError('Finding not found')
    finding = findings[0]
    if finding['Id'] != detail['id'] or finding['AccountId'] != os.environ['ACCOUNT_ID'] or finding['Region'] != os.environ['AWS_REGION']:
        raise ValueError('Finding identity mismatch')
    return finding


def eligible(finding):
    age = (c.now() - c.timestamp(finding['Service']['EventLastSeen'])).total_seconds()
    allowed = {s.strip() for s in os.environ['FINDING_TYPES'].split(',') if s.strip()}
    return (finding['Resource']['ResourceType'] == 'Instance' and not finding['Service'].get('Archived', False)
            and finding['Type'] in allowed and finding['Severity'] >= 7 and 0 <= age <= 1800)


def instance(instance_id):
    result = c.client('ec2').describe_instances(InstanceIds=[instance_id])
    found = [i for r in result['Reservations'] for i in r['Instances']]
    if len(found) != 1 or found[0]['InstanceId'] != instance_id:
        raise ValueError('Instance identity mismatch')
    return found[0]


def group_set(eni):
    return sorted(g['GroupId'] for g in eni['Groups'])


def preflight(info):
    tags = {t['Key']: t['Value'] for t in info.get('Tags', [])}
    if tags.get('SecurityResponse') != 'auto-isolate' or tags.get('SecurityProtected') == 'true':
        raise ValueError('Instance is not approved for automatic isolation')
    if 'aws:autoscaling:groupName' in tags:
        raise ValueError('Auto Scaling requires an application-specific response plan')
    ids = [n['NetworkInterfaceId'] for n in info.get('NetworkInterfaces', [])]
    if not ids:
        raise ValueError('No instance ENIs')
    enis = c.client('ec2').describe_network_interfaces(NetworkInterfaceIds=ids)['NetworkInterfaces']
    if sorted(e['NetworkInterfaceId'] for e in enis) != sorted(ids):
        raise ValueError('Missing ENI')
    groups = configuration()
    import json
    endpoints = set(json.loads(os.environ['ENDPOINT_GROUP_IDS']))
    plan = []
    for eni in enis:
        if eni.get('RequesterManaged') or eni.get('InterfaceType', 'interface') != 'interface':
            raise ValueError('Unsupported/service-managed ENI')
        if eni.get('Attachment', {}).get('InstanceId') != info['InstanceId']:
            raise ValueError('ENI attachment mismatch')
        isolation = groups.get(eni['VpcId'])
        if not isolation:
            raise ValueError('No pre-approved isolation group in VPC')
        sg = c.client('ec2').describe_security_groups(GroupIds=[isolation])['SecurityGroups']
        if len(sg) != 1 or sg[0]['VpcId'] != eni['VpcId']:
            raise ValueError('Isolation group VPC mismatch')
        if {t['Key']: t['Value'] for t in sg[0].get('Tags', [])}.get('SecurityIsolation') != 'approved':
            raise ValueError('Isolation group is not approved')
        # Allow only private management endpoint SG references / explicit private CIDRs.
        # Public CIDRs and unrestricted protocols make an isolation group unsafe.
        if sg[0].get('IpPermissions'):
            raise ValueError('Isolation group must not permit inbound application traffic')
        import ipaddress
        for rule in sg[0].get('IpPermissions', []) + sg[0].get('IpPermissionsEgress', []):
            if rule.get('IpProtocol') != 'tcp' or rule.get('FromPort') != 443 or rule.get('ToPort') != 443:
                raise ValueError('Isolation group must allow only explicit management HTTPS')
            if rule.get('PrefixListIds'):
                raise ValueError('Prefix-list routes need a separately reviewed isolation plan')
            for cidr in [r['CidrIp'] for r in rule.get('IpRanges', [])] + [r['CidrIpv6'] for r in rule.get('Ipv6Ranges', [])]:
                if not ipaddress.ip_network(cidr).is_private:
                    raise ValueError('Isolation group permits public traffic')
            if rule.get('IpRanges') or rule.get('Ipv6Ranges'):
                raise ValueError('Use endpoint security-group references instead of broad CIDRs')
            for pair in rule.get('UserIdGroupPairs', []):
                if pair['GroupId'] not in endpoints or pair.get('UserId', os.environ['ACCOUNT_ID']) != os.environ['ACCOUNT_ID']:
                    raise ValueError('Isolation egress endpoint group is not approved')
        plan.append({'eni': eni['NetworkInterfaceId'], 'before': group_set(eni), 'after': [isolation]})
    return plan


def handler(event, context):
    finding = verified_finding(event)
    c.evidence('incidents/guardduty', finding)
    ident = c.incident_id('guardduty', finding['Id'])
    target = finding.get('Resource', {}).get('InstanceDetails', {}).get('InstanceId')
    if not eligible(finding):
        c.notify(c.incident_id('guardduty-notice', finding['Id'] + finding['UpdatedAt']), 'P2',
                 'GuardDuty finding: notification only', {'type': finding['Type'], 'instance': target})
        return {'status': 'NOTIFIED', 'incident_id': ident}
    control = c.table().get_item(Key={'pk': 'CONTROL#response'}, ConsistentRead=True).get('Item', {})
    if control.get('enabled') is False:
        c.notify(c.incident_id('response-paused', ident), 'P1', 'Automatic response paused: critical finding requires manual action')
        return {'status': 'PAUSED'}
    # Notification failure must not suppress an approved critical isolation.
    notification_error = None
    try:
        c.notify(ident, 'P1', 'Verified critical finding: isolation requested', {'finding': finding['Id'], 'instance': target})
    except Exception as exc:
        notification_error = c.error_code(exc)
    pk = 'ISOLATION#' + target
    lease = uuid.uuid4().hex
    current = c.table().get_item(Key={'pk': pk}, ConsistentRead=True).get('Item')
    if current and current['status'] in ('ISOLATED', 'PARTIAL', 'ISOLATING', 'RESTORING'):
        if current['status'] == 'ISOLATED':
            info = instance(target)
            if {n['NetworkInterfaceId']: group_set(n) for n in info['NetworkInterfaces']} != {p['eni']: p['after'] for p in current['plan']}:
                c.notify(c.incident_id('isolation-drift', target + finding['UpdatedAt']), 'P1', 'Isolation drift requires immediate review')
        # Never overwrite the original before-SG snapshot. Retry partial work through the recovery handler.
        return {'status': current['status'], 'incident_id': current['incident_id']}
    if current and current['status'] == 'RESTORED':
        if current['finding_id'] == finding['Id'] and c.timestamp(finding['UpdatedAt']) <= c.timestamp(current['restored_at']):
            return {'status': 'STALE_AFTER_RESTORE'}
    try:
        plan = preflight(instance(target))
        record = {'pk': pk, 'instance_id': target, 'incident_id': ident, 'finding_id': finding['Id'], 'detector_id': event['detail']['service']['detectorId'],
                  'status': 'ISOLATING', 'lease': lease, 'started_at': c.now().isoformat(), 'plan': plan}
        record['before_evidence'] = c.evidence('incidents/isolation-before', {'finding': finding, 'state': record})
        c.table().put_item(Item=record, ConditionExpression='attribute_not_exists(pk) OR #s=:restored OR #s=:blocked',
                           ExpressionAttributeNames={'#s': 'status'},
                           ExpressionAttributeValues={':restored': 'RESTORED', ':blocked': 'BLOCKED'})
    except Exception as exc:
        if c.conditional(exc):
            return {'status': 'ALREADY_IN_PROGRESS'}
        c.notify(c.incident_id('blocked', ident), 'P1', 'ISOLATION_BLOCKED: approval, permissions or evidence unavailable',
                 {'error': c.error_code(exc), 'instance': target})
        return {'status': 'BLOCKED'}
    return complete_isolation(record, notification_error)


def complete_isolation(record, notification_error=None):
    plan, lease, ident, target = record['plan'], record['lease'], record['incident_id'], record['instance_id']
    errors = []
    for step in plan:
        try:
            control = c.table().get_item(Key={'pk': 'CONTROL#response'}, ConsistentRead=True).get('Item', {})
            if control.get('enabled') is False:
                raise PermissionError('Automatic response paused during isolation')
            c.client('ec2').modify_network_interface_attribute(NetworkInterfaceId=step['eni'], Groups=step['after'])
        except Exception as exc:
            errors.append({'eni': step['eni'], 'error': c.error_code(exc)})
    try:
        observed = c.client('ec2').describe_network_interfaces(NetworkInterfaceIds=[p['eni'] for p in plan])['NetworkInterfaces']
        if {n['NetworkInterfaceId']: group_set(n) for n in observed} != {p['eni']: p['after'] for p in plan}:
            errors.append({'error': 'PostChangeMismatch'})
        proof = c.evidence('incidents/isolation-after', {'plan': plan, 'observed': observed, 'errors': errors})
    except Exception as exc:
        errors.append({'error': c.error_code(exc)})
        proof = {'unavailable': True}
    status = 'PARTIAL' if errors else 'ISOLATED'
    c.table().update_item(Key={'pk': record['pk']}, UpdateExpression='SET #s=:s, after_evidence=:e, errors=:errors',
                         ConditionExpression='lease=:lease', ExpressionAttributeNames={'#s': 'status'},
                         ExpressionAttributeValues={':s': status, ':e': proof, ':errors': errors, ':lease': lease})
    c.notify(c.incident_id('isolation-result', ident + lease), 'P1', status + ': existing tracked connections may remain',
             {'instance': target, 'errors': errors, 'notification_error': notification_error})
    return {'status': status, 'incident_id': ident}


def restore(event, context):
    """Invoke only via a separate function accessible to the existing human approver role.

    Caller identity is recorded by CloudTrail Lambda data events; payload strings are not authorization.
    """
    if os.environ.get('FUNCTION_PURPOSE') != 'restore':
        raise PermissionError('Wrong function purpose')
    target, ident = event['instance_id'], event['approved_incident_id']
    pk = 'ISOLATION#' + target
    record = c.table().get_item(Key={'pk': pk}, ConsistentRead=True)['Item']
    if record['incident_id'] != ident or record['status'] not in ('ISOLATED', 'PARTIAL', 'RESTORING'):
        raise ValueError('Incident/status mismatch; manual recovery required')
    if event.get('execute') is not True:
        return {'status': 'PREVIEW', 'plan': record['plan']}
    info = instance(target)
    observed = {n['NetworkInterfaceId']: group_set(n) for n in info['NetworkInterfaces']}
    expected = {p['eni']: p['after'] for p in record['plan']}
    original = {p['eni']: p['before'] for p in record['plan']}
    valid = set(observed) == set(expected) and all(
        observed[eni] == expected[eni] or record['status'] in ('PARTIAL', 'RESTORING') and observed[eni] == original[eni]
        for eni in observed)
    if not valid:
        raise ValueError('ENI/SG drift; refusing to overwrite another administrator change')
    if record['status'] == 'RESTORING' and int(record.get('restore_lease_until', 0)) > int(c.now().timestamp()):
        raise ValueError('Another restore invocation is still active')
    proof = c.evidence('incidents/restore-approval', {'incident_id': ident, 'instance_id': target,
                                                  'lambda_request_id': context.aws_request_id,
                                                  'reported_approver': event.get('reported_approver'), 'plan': record['plan']})
    c.table().update_item(Key={'pk': pk}, UpdateExpression='SET #s=:restoring, approval_evidence=:proof, restore_lease_until=:until',
                         ConditionExpression='#s=:isolated OR #s=:partial OR (#s=:restoring AND restore_lease_until<:now)',
                         ExpressionAttributeNames={'#s': 'status'},
                         ExpressionAttributeValues={':restoring': 'RESTORING', ':proof': proof, ':isolated': 'ISOLATED', ':partial': 'PARTIAL', ':until': int(c.now().timestamp()) + 360, ':now': int(c.now().timestamp())})
    try:
        for step in record['plan']:
            c.client('ec2').modify_network_interface_attribute(NetworkInterfaceId=step['eni'], Groups=step['before'])
        result = c.client('ec2').describe_network_interfaces(NetworkInterfaceIds=list(expected))['NetworkInterfaces']
        if {n['NetworkInterfaceId']: group_set(n) for n in result} != {p['eni']: p['before'] for p in record['plan']}:
            raise ValueError('Restore verification failed')
        proof = c.evidence('incidents/restore-after', {'incident_id': ident, 'observed': result})
        c.table().update_item(Key={'pk': pk}, UpdateExpression='SET #s=:s, restored_at=:t, restore_evidence=:proof',
                             ExpressionAttributeNames={'#s': 'status'},
                             ExpressionAttributeValues={':s': 'RESTORED', ':t': c.now().isoformat(), ':proof': proof})
    except Exception:
        c.notify(c.incident_id('restore-failure', ident + context.aws_request_id), 'P1', 'RESTORE_PARTIAL: manual recovery required')
        raise
    return {'status': 'RESTORED'}


def resume(event, context):
    """Explicit recovery of an approved partial isolation, preserving the original before snapshot."""
    target = event['instance_id']
    pk = 'ISOLATION#' + target
    record = c.table().get_item(Key={'pk': pk}, ConsistentRead=True)['Item']
    if record['incident_id'] != event['incident_id'] or record['status'] not in ('PARTIAL', 'ISOLATING'):
        raise ValueError('Incident is not eligible for isolation recovery')
    if record['status'] == 'ISOLATING' and (c.now() - c.timestamp(record['started_at'])).total_seconds() < 360:
        raise ValueError('An isolation invocation may still be active')
    finding = c.client('guardduty').get_findings(DetectorId=record['detector_id'], FindingIds=[record['finding_id']])['Findings'][0]
    if finding['AccountId'] != os.environ['ACCOUNT_ID'] or finding['Region'] != os.environ['AWS_REGION'] or not eligible(finding):
        raise ValueError('Critical finding is no longer verified; primary-admin review required')
    if finding['Resource']['InstanceDetails']['InstanceId'] != target:
        raise ValueError('Finding target mismatch')
    current = preflight(instance(target))
    expected = {p['eni']: p for p in record['plan']}
    if set(expected) != {p['eni'] for p in current} or any(
        p['after'] != expected[p['eni']]['after'] or p['before'] not in (expected[p['eni']]['before'], expected[p['eni']]['after'])
        for p in current):
        raise ValueError('ENI configuration drift during partial isolation')
    if event.get('execute') is not True:
        return {'status': 'PREVIEW', 'plan': record['plan']}
    c.evidence('incidents/isolation-resume', {'incident_id':record['incident_id'], 'request_id':context.aws_request_id, 'observed':current})
    previous_lease = record['lease']
    record.update({'lease':uuid.uuid4().hex, 'status':'ISOLATING', 'started_at':c.now().isoformat()})
    c.table().put_item(Item=record, ConditionExpression='lease=:prior', ExpressionAttributeValues={':prior':previous_lease})
    return complete_isolation(record)
