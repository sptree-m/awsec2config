import base64
import copy
import datetime as dt
from decimal import Decimal
import gzip
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lambda_src'))
import common as c
import archive
import detection
import response
import operations

NOW=dt.datetime(2026,11,1,9,tzinfo=dt.timezone.utc)
INSTANCE='i-0123456789abcdef0'
ENV={'ACCOUNT_ID':'123456789012','AWS_REGION':'ap-northeast-1','ARCHIVE_BUCKET':'test-archive',
     'KMS_KEY_ARN':'arn:aws:kms:ap-northeast-1:123456789012:key/test-key','STATE_TABLE':'test-state',
     'NOTIFICATION_TOPIC':'arn:aws:sns:ap-northeast-1:123456789012:test',
     'LOG_GROUPS':'["/ec2/security/ubuntu/auth"]','INSTANCE_IDS':json.dumps([INSTANCE]),
     'ISOLATION_GROUPS':'{"vpc-test":"sg-isolation"}','ENDPOINT_GROUP_IDS':'["sg-endpoint"]',
     'FINDING_TYPES':'Backdoor:EC2/C&CActivity.B','FUNCTION_PURPOSE':'restore'}

class AwsError(Exception):
    def __init__(self,code):
        self.response={'Error':{'Code':code}}
        super().__init__(code)

class Table:
    def __init__(self): self.items={}
    def get_item(self,Key,**kwargs): return {'Item':copy.deepcopy(self.items[Key['pk']])} if Key['pk'] in self.items else {}
    def put_item(self,Item,ConditionExpression=None,ExpressionAttributeValues=None,**kwargs):
        prior=self.items.get(Item['pk'])
        if ConditionExpression=='attribute_not_exists(pk)' and prior: raise AwsError('ConditionalCheckFailedException')
        if ConditionExpression and ConditionExpression.startswith('job_id='):
            if not prior or prior['job_id']!=ExpressionAttributeValues.get(':id',ExpressionAttributeValues.get(':old')):
                raise AwsError('ConditionalCheckFailedException')
            if ':owner' in ExpressionAttributeValues and prior.get('lease_owner')!=ExpressionAttributeValues[':owner']:
                raise AwsError('ConditionalCheckFailedException')
        self.items[Item['pk']]=copy.deepcopy(Item)
        return {}
    def update_item(self,Key,UpdateExpression,ExpressionAttributeValues=None,ExpressionAttributeNames=None,ConditionExpression=None,**kwargs):
        row=self.items.setdefault(Key['pk'],{'pk':Key['pk']})
        values=ExpressionAttributeValues or {}; names=ExpressionAttributeNames or {}
        if ConditionExpression and 'lease_until<:now' in ConditionExpression and row.get('lease_until',0)>=values[':now']:
            raise AwsError('ConditionalCheckFailedException')
        if ConditionExpression=='lease_owner=:owner' and row.get('lease_owner')!=values[':owner']:
            raise AwsError('ConditionalCheckFailedException')
        if UpdateExpression.startswith('REMOVE '):
            for name in UpdateExpression[7:].split(','): row.pop(name.strip(),None)
        elif UpdateExpression.startswith('SET '):
            for expr in UpdateExpression[4:].split(','):
                name,key=expr.strip().split('='); row[names.get(name,name)]=copy.deepcopy(values[key])
        return {'Attributes':copy.deepcopy(row)}
    def query(self,**kwargs): return {'Items':[copy.deepcopy(r) for r in self.items.values() if r.get('incident_status')=='OPEN']}

class EC2:
    def __init__(self):
        self.enis=[{'NetworkInterfaceId':'eni-one','VpcId':'vpc-test','Groups':[{'GroupId':'sg-original-one'}],
                    'Attachment':{'InstanceId':INSTANCE},'InterfaceType':'interface'},
                   {'NetworkInterfaceId':'eni-two','VpcId':'vpc-test','Groups':[{'GroupId':'sg-original-two'}],
                    'Attachment':{'InstanceId':INSTANCE},'InterfaceType':'interface'}]
        self.tags=[{'Key':'SecurityResponse','Value':'auto-isolate'}]; self.writes=[]; self.fail=None
        self.sg={'GroupId':'sg-isolation','VpcId':'vpc-test','Tags':[{'Key':'SecurityIsolation','Value':'approved'}],
                 'IpPermissions':[], 'IpPermissionsEgress':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,
                                                          'UserIdGroupPairs':[{'GroupId':'sg-endpoint','UserId':ENV['ACCOUNT_ID']}]}]}
    def describe_instances(self,**kwargs):
        return {'Reservations':[{'Instances':[{'InstanceId':INSTANCE,'Tags':self.tags,'NetworkInterfaces':copy.deepcopy(self.enis)}]}]}
    def describe_network_interfaces(self,**kwargs): return {'NetworkInterfaces':copy.deepcopy(self.enis)}
    def describe_security_groups(self,**kwargs): return {'SecurityGroups':[copy.deepcopy(self.sg)]}
    def modify_network_interface_attribute(self,NetworkInterfaceId,Groups):
        if NetworkInterfaceId==self.fail: raise AwsError('UnauthorizedOperation')
        self.writes.append((NetworkInterfaceId,Groups))
        for e in self.enis:
            if e['NetworkInterfaceId']==NetworkInterfaceId: e['Groups']=[{'GroupId':g} for g in Groups]

class Base(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.dict(os.environ,ENV).start()
        patch.object(c,'now',return_value=NOW).start()
        self.table=Table(); patch.object(c,'table',return_value=self.table).start()
        self.proof=patch.object(c,'evidence',return_value={'key':'proof','version_id':'version'}).start()
        self.notify=patch.object(c,'notify',return_value={'message_id':'published'}).start()
        self.context=MagicMock(aws_request_id='request-id'); self.context.get_remaining_time_in_millis.return_value=200000

class Isolation(Base):
    def setUp(self):
        super().setUp(); self.ec2=EC2()
        self.finding={'Id':'finding-one','AccountId':ENV['ACCOUNT_ID'],'Region':ENV['AWS_REGION'],
                      'UpdatedAt':NOW.isoformat(),'Type':'Backdoor:EC2/C&CActivity.B','Severity':8,
                      'Service':{'EventLastSeen':NOW.isoformat(),'Archived':False},
                      'Resource':{'ResourceType':'Instance','InstanceDetails':{'InstanceId':INSTANCE}}}
        self.guard=MagicMock(); self.guard.get_findings.return_value={'Findings':[self.finding]}
        patch.object(c,'client',side_effect=lambda name:{'ec2':self.ec2,'guardduty':self.guard}[name]).start()
        self.event={'source':'aws.guardduty','account':ENV['ACCOUNT_ID'],'region':ENV['AWS_REGION'],
                    'detail':{'id':'finding-one','service':{'detectorId':'detector-one'}}}
    def test_all_enis_replaced_and_human_restore(self):
        result=response.handler(self.event,self.context)
        self.assertEqual(result['status'],'ISOLATED'); self.assertEqual(len(self.ec2.writes),2)
        state=self.table.items['ISOLATION#'+INSTANCE]
        self.assertEqual(state['plan'][0]['before'],['sg-original-one'])
        preview=response.restore({'instance_id':INSTANCE,'approved_incident_id':result['incident_id']},self.context)
        self.assertEqual(preview['status'],'PREVIEW'); self.assertEqual(len(self.ec2.writes),2)
        restored=response.restore({'instance_id':INSTANCE,'approved_incident_id':result['incident_id'],'execute':True},self.context)
        self.assertEqual(restored['status'],'RESTORED'); self.assertEqual(self.ec2.enis[0]['Groups'][0]['GroupId'],'sg-original-one')
    def test_partial_failure_never_reports_isolated_and_can_restore(self):
        self.ec2.fail='eni-two'; result=response.handler(self.event,self.context)
        self.assertEqual(result['status'],'PARTIAL')
        self.ec2.fail=None
        result=response.restore({'instance_id':INSTANCE,'approved_incident_id':result['incident_id'],'execute':True},self.context)
        self.assertEqual(result['status'],'RESTORED')
    def test_failed_before_evidence_prevents_mutation(self):
        self.proof.side_effect=[{'key':'guard'}, {'key':'notify'}, RuntimeError('unavailable')]
        # notify is mocked; evidence is called for guard and isolation-before only.
        self.proof.side_effect=[{'key':'guard'},RuntimeError('unavailable')]
        result=response.handler(self.event,self.context)
        self.assertEqual(result['status'],'BLOCKED'); self.assertEqual(self.ec2.writes,[])
    def test_foreign_source_rejected(self):
        self.event['account']='999999999999'
        with self.assertRaises(ValueError): response.handler(self.event,self.context)
        self.guard.get_findings.assert_not_called(); self.assertEqual(self.ec2.writes,[])
    def test_low_or_stale_finding_only_notifies(self):
        self.finding['Severity']=6
        self.assertEqual(response.handler(self.event,self.context)['status'],'NOTIFIED')
        self.finding['Severity']=8; self.finding['Service']['EventLastSeen']=(NOW-dt.timedelta(hours=1)).isoformat()
        self.assertEqual(response.handler(self.event,self.context)['status'],'NOTIFIED'); self.assertFalse(self.ec2.writes)
    def test_unapproved_instance_is_not_modified(self):
        self.ec2.tags=[]
        self.assertEqual(response.handler(self.event,self.context)['status'],'BLOCKED'); self.assertFalse(self.ec2.writes)
    def test_world_open_isolation_group_is_rejected(self):
        self.ec2.sg['IpPermissionsEgress'][0]['IpRanges']=[{'CidrIp':'0.0.0.0/0'}]
        self.assertEqual(response.handler(self.event,self.context)['status'],'BLOCKED'); self.assertFalse(self.ec2.writes)
    def test_unapproved_endpoint_group_is_rejected(self):
        self.ec2.sg['IpPermissionsEgress'][0]['UserIdGroupPairs'][0]['GroupId']='sg-other'
        self.assertEqual(response.handler(self.event,self.context)['status'],'BLOCKED')
    def test_notification_failure_does_not_suppress_approved_isolation(self):
        self.notify.side_effect=[RuntimeError('sns down'),{'message_id':'result'}]
        self.assertEqual(response.handler(self.event,self.context)['status'],'ISOLATED')
    def test_restore_stops_on_foreign_change(self):
        result=response.handler(self.event,self.context); writes=len(self.ec2.writes)
        self.ec2.enis[0]['Groups']=[{'GroupId':'sg-admin-edit'}]
        with self.assertRaises(ValueError): response.restore({'instance_id':INSTANCE,'approved_incident_id':result['incident_id'],'execute':True},self.context)
        self.assertEqual(len(self.ec2.writes),writes)
    def test_paused_control_never_modifies(self):
        self.table.items['CONTROL#response']={'pk':'CONTROL#response','enabled':False}
        self.assertEqual(response.handler(self.event,self.context)['status'],'PAUSED'); self.assertFalse(self.ec2.writes)
    def test_duplicate_finding_preserves_original_before_snapshot(self):
        response.handler(self.event,self.context); before=copy.deepcopy(self.table.items['ISOLATION#'+INSTANCE])
        response.handler(self.event,self.context)
        self.assertEqual(self.table.items['ISOLATION#'+INSTANCE],before); self.assertEqual(len(self.ec2.writes),2)

    def test_protected_instance_never_modifies(self):
        self.ec2.tags.append({'Key':'SecurityProtected','Value':'true'})
        self.assertEqual(response.handler(self.event,self.context)['status'],'BLOCKED')
        self.assertFalse(self.ec2.writes)
    def test_partial_isolation_resume_preserves_before(self):
        self.ec2.fail='eni-two'; result=response.handler(self.event,self.context)
        before=copy.deepcopy(self.table.items['ISOLATION#'+INSTANCE]['plan'])
        self.ec2.fail=None
        request={'instance_id':INSTANCE,'incident_id':result['incident_id']}
        self.assertEqual(response.resume(request,self.context)['status'],'PREVIEW')
        self.assertEqual(response.resume({**request,'execute':True},self.context)['status'],'ISOLATED')
        self.assertEqual(self.table.items['ISOLATION#'+INSTANCE]['plan'],before)
    def test_restore_lease_blocks_second_invocation(self):
        result=response.handler(self.event,self.context)
        row=self.table.items['ISOLATION#'+INSTANCE]
        row.update(status='RESTORING',restore_lease_until=int(NOW.timestamp())+360)
        count=len(self.ec2.writes)
        with self.assertRaises(ValueError):
            response.restore({'instance_id':INSTANCE,'approved_incident_id':result['incident_id'],'execute':True},self.context)
        self.assertEqual(len(self.ec2.writes),count)

class Archives(Base):
    def setUp(self):
        super().setUp(); self.logs=MagicMock(); self.s3=MagicMock()
        self.logs.get_paginator.return_value.paginate.return_value=[{'logGroups':[{'logGroupName':'/ec2/security/ubuntu/auth','retentionInDays':400,'creationTime':0}]}]
        patch.object(c,'client',side_effect=lambda name:{'logs':self.logs,'s3':self.s3}[name]).start()
    def test_jst_previous_month_and_leap_year(self):
        start,end=c.previous_month('2028-03-01T09:00:00Z')
        self.assertEqual(start.isoformat(),'2028-02-01T00:00:00+09:00')
        self.assertEqual((end-start).days,29)
        self.assertEqual(start.astimezone(c.UTC).hour,15)
    def test_init_idempotent_and_failed_run_restart(self):
        event={'scheduled_time':NOW.isoformat(),'revision':'initial'}
        first=archive.start(event,self.context); again=archive.start(event,self.context)
        self.assertEqual(first,again)
        row=self.table.items[first['pk']]; row['status']='FAILED'
        restarted=archive.start(event,self.context)
        self.assertNotEqual(first['job_id'],restarted['job_id'])
    def test_correction_waits_for_active_initial(self):
        archive.start({'scheduled_time':NOW.isoformat(),'revision':'initial'},self.context)
        result=archive.start({'scheduled_time':NOW.isoformat(),'revision':'correction'},self.context)
        self.assertEqual(result['phase'],'WAIT_START')
    def test_retention_below_year_blocks_export(self):
        self.logs.get_paginator.return_value.paginate.return_value[0]['logGroups'][0]['retentionInDays']=90
        with self.assertRaises(ValueError): archive.start({'scheduled_time':NOW.isoformat()},self.context)
        self.logs.create_export_task.assert_not_called()
    def job(self):
        state=archive.start({'scheduled_time':NOW.isoformat()},self.context)
        return self.table.items[state['pk']]
    def test_foreign_export_quota_is_wait_not_new_task(self):
        job=self.job(); self.logs.describe_export_tasks.return_value={'exportTasks':[]}
        self.logs.create_export_task.side_effect=AwsError('LimitExceededException')
        self.assertEqual(archive.advance(job,self.context)['phase'],'WAIT'); self.assertNotIn('task_id',job)
    def test_recovery_rejects_wrong_task_destination(self):
        job=self.job(); self.logs.describe_export_tasks.return_value={'exportTasks':[{'taskName':f'awsec2-{job["job_id"]}-0','taskId':'foreign'}]}
        with self.assertRaises(ValueError): archive.advance(job,self.context)
        self.logs.create_export_task.assert_not_called()
    def test_decimal_checkpoint_uses_real_sdk_export_parameter_names(self):
        import boto3
        from botocore.stub import Stubber
        logs=boto3.client('logs',region_name=ENV['AWS_REGION'],aws_access_key_id='test',aws_secret_access_key='test')
        job=self.job(); job['index']=Decimal(0)
        chunk=job['chunks'][0]; chunk['from']=Decimal(chunk['from']); chunk['to_exclusive']=Decimal(chunk['to_exclusive'])
        expected={'taskName':f'awsec2-{job["job_id"]}-0','logGroupName':chunk['group'],'from':int(chunk['from']),
                  'to':int(chunk['to_exclusive'])-1,'destination':ENV['ARCHIVE_BUCKET'],'destinationPrefix':job['prefix']+'/exports/chunk=0'}
        with Stubber(logs) as stub:
            stub.add_response('describe_export_tasks',{'exportTasks':[]},{'limit':50})
            stub.add_response('create_export_task',{'taskId':'task-one'},expected)
            with patch.object(c,'client',return_value=logs): archive.advance(job,self.context)
            stub.assert_no_pending_responses()
        self.assertEqual(job['task_id'],'task-one')
    def gzip_head(self,data):
        return {'VersionId':'version','ContentLength':len(data),'ServerSideEncryption':'aws:kms', 'SSEKMSKeyId':ENV['KMS_KEY_ARN'],
                'LastModified':NOW,'ObjectLockMode':'COMPLIANCE','ObjectLockRetainUntilDate':NOW+dt.timedelta(days=400)}
    def test_concatenated_gzip_hash_and_retention_verified(self):
        raw=gzip.compress(b'one\n')+gzip.compress(b'two\n')
        self.s3.head_object.return_value=self.gzip_head(raw); self.s3.get_object.return_value={'Body':io.BytesIO(raw)}
        result=archive.verify_object('chunk.gz',self.context)
        self.assertEqual(result['expanded_bytes'],8); self.assertEqual(result['compressed_bytes'],len(raw))
    def test_bad_gzip_does_not_verify(self):
        raw=gzip.compress(b'data')[:-3]+b'xxx'
        self.s3.head_object.return_value=self.gzip_head(raw); self.s3.get_object.return_value={'Body':io.BytesIO(raw)}
        with self.assertRaises((gzip.BadGzipFile,EOFError)): archive.verify_object('bad.gz',self.context)
    def test_short_object_lock_rejected_before_read(self):
        raw=gzip.compress(b'data'); head=self.gzip_head(raw); head['ObjectLockRetainUntilDate']=NOW+dt.timedelta(days=90)
        self.s3.head_object.return_value=head
        with self.assertRaises(ValueError): archive.verify_object('bad.gz',self.context)
        self.s3.get_object.assert_not_called()

class Detection(Base):
    def test_parse_xml_and_ssh(self):
        xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID></System><EventData><Data Name="IpAddress">192.0.2.1</Data><Data Name="TargetUserName">test</Data></EventData></Event>'
        self.assertEqual(detection.parse(xml)['kind'],'failure')
        self.assertEqual(detection.parse('Failed password for invalid user test from 192.0.2.1 port 22')['user'],'test')
    def test_duplicate_failure_does_not_inflate_counter(self):
        ddb=MagicMock()
        def transact(TransactItems):
            receipt=TransactItems[0]['Put']['Item']; seen=receipt['pk']['S']
            countkey=TransactItems[1]['Update']['Key']['pk']['S']
            self.table.items[seen]={'pk':seen,'done':False,'counted':True}
            row=self.table.items.setdefault(countkey,{'pk':countkey,'failures':0}); row['failures']+=1
        ddb.transact_write_items.side_effect=transact
        patch.object(c,'client',return_value=ddb).start()
        batch={'owner':ENV['ACCOUNT_ID'],'messageType':'DATA_MESSAGE','logGroup':'/ec2/security/ubuntu/auth','logStream':INSTANCE,
               'logEvents':[{'id':'same-id','timestamp':int(NOW.timestamp()*1000),'message':'Failed password for test from 192.0.2.1 port 22'}]}
        event={'awslogs':{'data':base64.b64encode(gzip.compress(json.dumps(batch).encode())).decode()}}
        detection.handler(event,self.context); detection.handler(event,self.context)
        ddb.transact_write_items.assert_called_once()
        self.assertEqual(sum(x.get('failures',0) for x in self.table.items.values()),1)
    def test_sns_failure_retry_keeps_count_and_retries_notice(self):
        ddb=MagicMock()
        def transact(TransactItems):
            pk=TransactItems[0]['Put']['Item']['pk']['S']; counter=TransactItems[1]['Update']['Key']['pk']['S']
            self.table.items[pk]={'pk':pk,'done':False,'counted':True}; self.table.items[counter]={'pk':counter,'failures':10}
        ddb.transact_write_items.side_effect=transact; patch.object(c,'client',return_value=ddb).start()
        batch={'owner':ENV['ACCOUNT_ID'],'messageType':'DATA_MESSAGE','logGroup':'/ec2/security/ubuntu/auth','logStream':INSTANCE,
               'logEvents':[{'id':'retry-id','timestamp':int(NOW.timestamp()*1000),'message':'Failed password for test from 192.0.2.1 port 22'}]}
        event={'awslogs':{'data':base64.b64encode(gzip.compress(json.dumps(batch).encode())).decode()}}
        self.notify.side_effect=[RuntimeError('sns unavailable'),{'message_id':'retry'}]
        with self.assertRaises(RuntimeError): detection.handler(event,self.context)
        detection.handler(event,self.context)
        ddb.transact_write_items.assert_called_once(); self.assertEqual(self.notify.call_count,2)
    def test_control_message_has_no_side_effect(self):
        event={'awslogs':{'data':base64.b64encode(gzip.compress(b'{"messageType":"CONTROL_MESSAGE"}')).decode()}}
        self.assertEqual(detection.handler(event,self.context)['status'],'CONTROL'); self.notify.assert_not_called()

class ManagementChanges(Base):
    def event(self, action, request):
        return {'id':'event-one','account':ENV['ACCOUNT_ID'],'detail-type':'AWS API Call via CloudTrail',
                'detail':{'eventName':action,'requestParameters':request,'eventID':'cloudtrail-id'}}
    def test_retention_reduction_is_p1_and_unrelated_group_ignored(self):
        event=self.event('PutRetentionPolicy',{'logGroupName':'/ec2/security/ubuntu/auth','retentionInDays':30})
        self.assertEqual(detection.aws_change(event,self.context)['status'],'NOTIFIED')
        self.assertEqual(self.notify.call_args.args[1],'P1')
        event['detail']['requestParameters']['logGroupName']='unrelated'
        self.assertEqual(detection.aws_change(event,self.context)['status'],'UNRELATED')
    def test_failed_api_call_does_not_report_change(self):
        event=self.event('DisableKey',{}); event['detail']['errorCode']='AccessDenied'
        self.assertEqual(detection.aws_change(event,self.context)['status'],'FAILED_API_CALL_NO_CHANGE')
        self.proof.assert_not_called(); self.notify.assert_not_called()

class DeliveryFailure(Base):
    def test_no_dlq_delete_if_evidence_cannot_be_preserved(self):
        with patch.dict(os.environ,{'DELIVERY_DLQ_URL':'test-queue'}):
            sqs=MagicMock(); sqs.receive_message.return_value={'Messages':[{'MessageId':'id','Body':'original','ReceiptHandle':'receipt'}]}
            with patch.object(c,'client',return_value=sqs):
                self.proof.side_effect=RuntimeError('S3 denied')
                with self.assertRaises(RuntimeError): operations.handler({},self.context)
            sqs.delete_message.assert_not_called()

class Templates(unittest.TestCase):
    def test_template_is_reproducible_and_retains_archives(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('cfn_generator',ROOT/'infrastructure/generate_template.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        stored=json.loads((ROOT/'infrastructure/security-operations.json').read_text())
        self.assertEqual(stored,module.template)
        bucket=stored['Resources']['ArchiveBucket']; self.assertEqual(bucket['DeletionPolicy'],'Retain')
        self.assertEqual(bucket['Properties']['ObjectLockConfiguration']['Rule']['DefaultRetention']['Days'],400)
        self.assertFalse(any(r['Type'].startswith('AWS::IAM::') for r in stored['Resources'].values()))
        self.assertEqual(stored['Resources']['InitialMonthlySchedule']['Properties']['ScheduleExpressionTimezone'],'Asia/Tokyo')
        self.assertEqual(stored['Resources']['InitialMonthlySchedule']['Properties']['ScheduleExpression'],'cron(0 18 1 * ? *)')
    def test_role_mutations_are_eni_scoped_and_runtime_cannot_unpause(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('role_renderer',ROOT/'scripts/aws/render_role_policies.py')
        renderer=importlib.util.module_from_spec(spec); spec.loader.exec_module(renderer)
        config={'region':ENV['AWS_REGION'],'account_id':ENV['ACCOUNT_ID'],'approved_eni_ids':['eni-one'],
                'parameters':{'Prefix':'test','KmsKeyArn':ENV['KMS_KEY_ARN'],'NotificationTopicArn':ENV['NOTIFICATION_TOPIC']}}
        result=renderer.render(config)
        for role in ('ResponseRole','RestoreRole'):
            statements=result[role+'.policy.json']['Statement']
            mutation=[s for s in statements if s['Action']=='ec2:ModifyNetworkInterfaceAttribute']
            self.assertEqual(mutation[0]['Resource'],['arn:aws:ec2:ap-northeast-1:123456789012:network-interface/eni-one'])
        for role in ('ArchiveRole','DetectorRole','ResponseRole','RestoreRole'):
            for statement in result[role+'.policy.json']['Statement']:
                if 'dynamodb:PutItem' in statement['Action']:
                    self.assertNotIn('CONTROL#*',statement['Condition']['ForAllValues:StringLike']['dynamodb:LeadingKeys'])
        config['approved_eni_ids']=[]
        with self.assertRaises(ValueError):renderer.render(config)
    def test_runtime_has_no_terminate_or_global_security_group_mutation(self):
        # Safety contract for the response surface, including accidental expansion in future revisions.
        import ast
        tree=ast.parse((ROOT/'lambda_src/response.py').read_text())
        methods={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse(methods & {'terminate_instances','stop_instances','delete_security_group','revoke_security_group_ingress','authorize_security_group_ingress'})

if __name__=='__main__': unittest.main()
