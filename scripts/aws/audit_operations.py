#!/usr/bin/env python3
"""Read-only evidence report for the deployed central logging stack."""
import argparse
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
import sys


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--config',type=Path,required=True); p.add_argument('--output',type=Path,required=True); args=p.parse_args()
    config=json.loads(args.config.read_text()); params=config['parameters']
    import boto3
    session=boto3.Session(profile_name=config['profile'],region_name=config['region'])
    checks=[]; evidence={}
    def capture(name,service,method,kwargs,validator):
        try:
            value=getattr(session.client(service),method)(**kwargs); evidence[name]=value
            checks.append({'name':name,'status':'PASS' if validator(value) else 'FAIL','detail':'See raw evidence'})
        except Exception as exc:
            checks.append({'name':name,'status':'UNKNOWN','detail':getattr(exc,'response',{}).get('Error',{}).get('Code',type(exc).__name__)})
    capture('AWS identity','sts','get_caller_identity',{},lambda x:x['Account']==config['account_id'])
    prefix=params['Prefix']; bucket=f'{prefix}-logs-{config["account_id"]}-{config["region"]}'
    capture('Archive default retention','s3','get_object_lock_configuration',{'Bucket':bucket},
            lambda x:x['ObjectLockConfiguration'].get('Rule',{}).get('DefaultRetention',{}).get('Mode')=='COMPLIANCE' and x['ObjectLockConfiguration'].get('Rule',{}).get('DefaultRetention',{}).get('Days',0)>=400)
    capture('Archive versioning','s3','get_bucket_versioning',{'Bucket':bucket},lambda x:x.get('Status')=='Enabled')
    capture('Archive public access','s3','get_public_access_block',{'Bucket':bucket},lambda x:all(x['PublicAccessBlockConfiguration'].values()))
    capture('KMS key enabled','kms','describe_key',{'KeyId':params['KmsKeyArn']},lambda x:x['KeyMetadata']['KeyState']=='Enabled')
    for name,day in [('initial',1),('correction',4)]:
        capture('JST '+name+' schedule','scheduler','get_schedule',{'Name':prefix+'-monthly-'+name},
                lambda x,day=day:x['State']=='ENABLED' and x['ScheduleExpressionTimezone']=='Asia/Tokyo' and x['ScheduleExpression']==f'cron(0 18 {day} * ? *)')
    capture('GuardDuty response rule','events','describe_rule',{'Name':prefix+'-guardduty'},lambda x:x['State']=='ENABLED')
    for group in json.loads(params['ActiveLogGroups']):
        capture(group+' retention','logs','describe_log_groups',{'logGroupNamePrefix':group},
                lambda x,g=group:any(i['logGroupName']==g and i.get('retentionInDays',0)>=400 for i in x['logGroups']))
        capture(group+' raw subscription','logs','describe_subscription_filters',{'logGroupName':group},
                lambda x:any('firehose:' in i['destinationArn'] for i in x['subscriptionFilters']))
    capture('Notification subscriptions','sns','list_subscriptions_by_topic',{'TopicArn':params['NotificationTopicArn']},
            lambda x:len([i for i in x['Subscriptions'] if i['SubscriptionArn']!='PendingConfirmation'])>=2)
    checks.append({'name':'End-to-end delivery and isolation','status':'UNKNOWN','detail':'Run acceptance tests; configuration presence alone does not prove delivery or active connection termination'})
    args.output.mkdir(parents=True,mode=0o700,exist_ok=False); args.output.chmod(0o700)
    def serial(value):
        if isinstance(value,dt.datetime):return value.isoformat()
        return str(value)
    record={'time_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'checks':checks,'evidence':evidence}
    (args.output/'report.json').write_text(json.dumps(record,ensure_ascii=False,indent=2,default=serial))
    rows=''.join(f'<tr><td>{html.escape(i["name"])}</td><td>{i["status"]}</td><td>{html.escape(i["detail"])}</td></tr>' for i in checks)
    (args.output/'report.html').write_text('<!doctype html><meta charset="utf-8"><h1>Central logging audit</h1><table border="1">'+rows+'</table>')
    files=[args.output/'report.json',args.output/'report.html']
    (args.output/'sha256.json').write_text(json.dumps({f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files},indent=2))
    for f in args.output.iterdir():f.chmod(0o600)
    print(args.output)
    return 2 if any(c['status']!='PASS' for c in checks) else 0

if __name__=='__main__': sys.exit(main())
