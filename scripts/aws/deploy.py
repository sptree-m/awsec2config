#!/usr/bin/env python3
"""Build a reviewable CloudFormation change set. No automatic AWS execution without --execute."""
import argparse
import json
from pathlib import Path
import subprocess
import uuid
import sys

ROOT=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--execute',action='store_true',help='Execute the created change set after displaying it')
    args=p.parse_args(); config=json.loads(args.config.read_text())
    if 'REPLACE' in json.dumps(config): raise ValueError('Replace all example placeholders')
    import boto3
    session=boto3.Session(profile_name=config['profile'],region_name=config['region'])
    if session.client('sts').get_caller_identity()['Account']!=config['account_id']: raise ValueError('Account mismatch')
    cf=session.client('cloudformation'); stack=config['stack_name']
    try:
        cf.describe_stacks(StackName=stack); kind='UPDATE'
    except Exception as exc:
        code=getattr(exc,'response',{}).get('Error',{}).get('Code')
        if code=='ValidationError' and 'does not exist' in str(exc): kind='CREATE'
        else: raise
    name='security-'+uuid.uuid4().hex
    body=(ROOT/'infrastructure/security-operations.json').read_text()
    # Template exceeds the inline API size as it grows; use the existing code bucket for reviewed template bytes.
    key='changesets/'+name+'/security-operations.json'
    session.client('s3').put_object(Bucket=config['parameters']['CodeBucket'],Key=key,Body=body.encode(),ContentType='application/json')
    template_url=f'https://{config["parameters"]["CodeBucket"]}.s3.{config["region"]}.amazonaws.com/{key}'
    cf.create_change_set(StackName=stack,ChangeSetName=name,ChangeSetType=kind,TemplateURL=template_url,
        Parameters=[{'ParameterKey':k,'ParameterValue':v} for k,v in config['parameters'].items()],
        Description='Reviewed EC2 security operations v0.2.0. Creates 400-day COMPLIANCE archive retention.')
    cf.get_waiter('change_set_create_complete').wait(StackName=stack,ChangeSetName=name)
    result=cf.describe_change_set(StackName=stack,ChangeSetName=name)
    print(json.dumps({'change_set':result['ChangeSetId'],'status':result['Status'],'changes':result.get('Changes',[])},default=str,indent=2))
    if args.execute:
        cf.execute_change_set(StackName=stack,ChangeSetName=name)
        print('Execution started. Use CloudFormation events and deployment acceptance checks before production use.')
    else:
        print('No resource changes executed. Execute this exact reviewed change set with AWS CLI when authorized.')
    return 0


if __name__=='__main__':
    try: sys.exit(main())
    except Exception as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr); sys.exit(1)
