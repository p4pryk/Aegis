"""Read-only live inventory and temporary file-adapter coverage fixtures on the VM."""
import json,os,pathlib,sys,tempfile,time
sys.path.insert(0,'/opt/defense-agent')
import agent,application_sources,console,coverage_check as coverage
checks=[]
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
end=time.time()+30;report={}
while time.time()<end:
    data=console.read_snapshot('/var/lib/defense-agent/incidents.db')
    report=data.get('sensor_health',{}).get('coverage_check',{})
    if report.get('rows'):break
    time.sleep(.5)
check('Installed background probe publishes a bounded inventory',bool(report.get('rows')) and len(report['rows'])<=32)
check('Installed source screen exposes configuration coverage','COVERAGE CHECK' in '\n'.join(console.source_lines(data,120,time.time())))
facts=coverage.inventory()
check('Real service metadata is available',facts['services_available'])
check('Actual kernel audit rule keys are inspected',facts['rules'] is not None and 'lab_root_exec' in facts['rules'])
with tempfile.TemporaryDirectory(prefix='aegis-coverage-fixture-') as directory:
    root=pathlib.Path(directory);path=root/'events.jsonl';source=dict(name='fixture',application='fixture',path=str(path),format='jsonl',owner_uid=os.geteuid())
    config=dict(agent.DEFAULTS,data_dir=str(root),application_sources=[source]);health={'sources':[]}
    def app_state():
        result=coverage.assess(config,health,facts)
        return next(r['status'] for r in result['rows'] if r['name']=='App fixture')
    check('Configured missing file is reported as missing',app_state()=='MISSING')
    path.touch(mode=0o600)
    check('Quiet empty file is not claimed to be observed',app_state()=='CONFIGURED')
    store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None);files=application_sources.Applications(engine)
    try:
        path.write_text(json.dumps(dict(time=time.time(),event='security_alert',message='SECRET_DO_NOT_COLLECT'))+'\n')
        files.poll(True);health['sources']=files.sources()
        observed=coverage.assess(config,health,facts)
        check('Real adapter intake changes coverage to observed',app_state()=='OBSERVED')
        check('Report contains no log payloads','SECRET_DO_NOT_COLLECT' not in json.dumps(observed))
        with path.open('a') as out:out.write('native unsupported log format\n')
        files.poll(True);health['sources']=files.sources()
        check('Unsupported records require format review',app_state()=='FORMAT REVIEW')
        path.chmod(0o666);check('Unsafe permissions are identified',app_state()=='UNSAFE')
        path.unlink();path.symlink_to('/etc/passwd');check('Symlink is refused without reading the target',app_state()=='UNSAFE')
        with __import__('unittest.mock',fromlist=['patch']).patch.object(coverage,'CATALOG',(('Fixture service',(),(str(path),),'Review fixture adapter.'),)):
            config['application_sources']=[]
            check('Detected source is never enrolled automatically',any(r['status']=='NEEDS CONFIG' for r in coverage.assess(config,health,facts)['rows']) and config['application_sources']==[])
    finally:files.close();store.db.close()
check('Stale inventory is explicitly unknown','stale' in '\n'.join(coverage.lines(report,120,report['time']+121)))
print(json.dumps({'passed':sum(checks),'total':len(checks)}))
