#!/usr/bin/env python3
"""Explicit operator actions. Uses existing AWS identities; creates/deletes no IAM resources."""
import argparse
import datetime as dt
import json
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', required=True)
    p.add_argument('--region', required=True)
    p.add_argument('--prefix', default='awsec2config')
    sub = p.add_subparsers(dest='command', required=True)
    ack = sub.add_parser('ack'); ack.add_argument('--incident-id', required=True)
    restore = sub.add_parser('restore'); restore.add_argument('--instance-id', required=True)
    restore.add_argument('--incident-id', required=True); restore.add_argument('--execute', action='store_true')
    resume = sub.add_parser('resume-isolation'); resume.add_argument('--instance-id', required=True)
    resume.add_argument('--incident-id', required=True); resume.add_argument('--execute', action='store_true')
    month = sub.add_parser('restart-month'); month.add_argument('--month', required=True)
    month.add_argument('--revision', choices=['initial', 'correction'], default='initial')
    pause = sub.add_parser('pause'); pause.add_argument('--execute', action='store_true')
    args = p.parse_args()
    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    identity = session.client('sts').get_caller_identity()
    table = session.resource('dynamodb').Table(args.prefix + '-state')
    if args.command == 'ack':
        table.update_item(Key={'pk': 'INCIDENT#' + args.incident_id},
                          UpdateExpression='SET incident_status=:s, acknowledged_at=:t, reported_approver=:a',
                          ConditionExpression='attribute_exists(pk)',
                          ExpressionAttributeValues={':s': 'ACKED', ':t': dt.datetime.now(dt.timezone.utc).isoformat(), ':a': identity['Arn']})
        print('Acknowledged. AWS caller attribution requires CloudTrail DynamoDB data-event coverage.')
    elif args.command in ('restore', 'resume-isolation'):
        payload = {'instance_id': args.instance_id, 'approved_incident_id': args.incident_id,
                   'execute': args.execute, 'reported_approver': identity['Arn']}
        if args.command == 'resume-isolation':
            payload['incident_id'] = args.incident_id
        suffix = '-resume' if args.command == 'resume-isolation' else '-restore'
        response = session.client('lambda').invoke(FunctionName=args.prefix + suffix,
                                                   Payload=json.dumps(payload).encode())
        result = response['Payload'].read().decode()
        print(result)
        return 1 if response.get('FunctionError') else 0
    elif args.command == 'restart-month':
        date = dt.datetime.strptime(args.month, '%Y-%m')
        next_month = date.replace(year=date.year + 1, month=1) if date.month == 12 else date.replace(month=date.month + 1)
        local = next_month.replace(tzinfo=dt.timezone(dt.timedelta(hours=9)), hour=18)
        arn = f'arn:aws:states:{args.region}:{identity["Account"]}:stateMachine:{args.prefix}-monthly'
        result = session.client('stepfunctions').start_execution(stateMachineArn=arn,
            input=json.dumps({'revision': args.revision, 'scheduled_time': local.isoformat()}))
        print(result['executionArn'])
    else:
        names = [args.prefix + '-monthly-initial', args.prefix + '-monthly-correction', args.prefix + '-operations']
        print(json.dumps({'disable_response': True, 'schedules': names, 'guardduty_rule': args.prefix + '-guardduty'}))
        if not args.execute:
            return 0
        table.put_item(Item={'pk': 'CONTROL#response', 'enabled': False,
                             'reported_approver': identity['Arn'], 'updated_at': dt.datetime.now(dt.timezone.utc).isoformat()})
        scheduler = session.client('scheduler')
        errors = []
        for name in names:
            try:
                current = scheduler.get_schedule(Name=name)
                allowed = ('Name','GroupName','ScheduleExpression','ScheduleExpressionTimezone','FlexibleTimeWindow','Target','Description','StartDate','EndDate','KmsKeyArn','ActionAfterCompletion')
                request = {k: current[k] for k in allowed if k in current}
                scheduler.update_schedule(**request, State='DISABLED')
            except Exception as exc:
                errors.append({'schedule': name, 'error': type(exc).__name__})
        try:
            session.client('events').disable_rule(Name=args.prefix + '-guardduty')
        except Exception as exc:
            errors.append({'rule': 'guardduty', 'error': type(exc).__name__})
        print(json.dumps({'errors': errors, 'note': 'In-flight workflows and log delivery remain. Stop executions explicitly if required; do not delete archives.'}))
        return 2 if errors else 0
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        sys.exit(1)
