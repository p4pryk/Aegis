import json,os,pathlib,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,console,queue_view

class QueueView(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(agent.DEFAULTS,data_dir=self.tmp.name,ai_results_dir=self.tmp.name)
        self.store=agent.Store(self.c);self.addCleanup(self.store.db.close)
        self.engine=agent.CorrelatedEngine(self.c,self.store,None);self.now=time.time()
    def populate(self,n=1):
        for i in range(n):
            key=f'{i:024x}'
            self.store.db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(key,self.now-100,self.now-100,'application_activity','fixture',1,'awaiting_analysis',json.dumps({'allowed_actions':[]}), '{}','{}'))
            self.store.db.execute('INSERT INTO analysis_queue VALUES (?,?,?,?,?)',(key,1,self.now-100,self.engine.boot_id,'BUDGET EXHAUSTED'))
        self.store.db.commit()
        self.store.state('heartbeat',dict(time=self.now,boot_id=self.engine.boot_id,analysis_window=90,queue_window=7200))
    def data(self):return console.read_snapshot(self.store.path)
    def text(self,data=None):return '\n'.join(queue_view.lines(data or self.data(),104,self.now))
    def test_queue_counts_are_not_limited_to_40_recent_cases(self):
        self.populate(55);data=self.data()
        self.assertEqual(len(data['cases']),40);self.assertEqual(len(data['queue_rows']),55)
        self.assertEqual(data['queue_counts']['awaiting_analysis'],55)
        self.assertIn('Awaiting assessment: 55',self.text(data))
    def test_time_window_does_not_grant_execution_and_stale_heartbeat_is_unknown(self):
        self.populate();data=self.data();row=data['queue_rows'][0]
        self.assertIn('HISTORICAL ONLY',self.text(data));row['queued_at']=self.now-5;row['actions']=1
        self.assertIn('executor checks still required',self.text(data))
        row['boot_id']='previous-boot';self.assertIn('HISTORICAL ONLY',self.text(data))
        data['heartbeat']['time']=self.now-20
        self.assertIn('Timing unknown',self.text(data));self.assertNotIn('window open',self.text(data))
    def test_expiry_missing_registration_and_zero_actions(self):
        self.populate();data=self.data();row=data['queue_rows'][0];row['queued_at']=self.now-7201
        self.assertIn('QUEUE EXPIRED',self.text(data))
        row['queued_at']=self.now;self.assertIn('REVIEW ONLY',self.text(data))
        row['queued_at']=None;self.assertIn('not yet registered',self.text(data))
    def test_overload_warning_is_historical_and_survives_restart(self):
        self.populate();self.store.state('correlation_overload',dict(time=self.now-30,rejections=4))
        self.engine=agent.CorrelatedEngine(self.c,self.store,None)
        self.assertIn('4 attempts',self.text());self.assertIn('historical',self.text())
    def test_fixed_header_scroll_and_safe_terminal_text(self):
        self.populate(10);data=self.data();data['queue_rows'][0]['subject']='evil\x1b[2J'
        for width,height in ((104,32),(52,24)):
            a=console.render(data,width,height,mode='queue',now=self.now)
            b=console.render(data,width,height,mode='queue',offset=10,now=self.now)
            self.assertEqual(a[:len(console.logo(width))+4],b[:len(console.logo(width))+4])
            self.assertNotEqual(a,b);self.assertEqual(len(a),height)
            self.assertTrue(all(console.cells(line)==width for line in a));self.assertNotIn('\x1b','\n'.join(a))
    def test_older_database_reports_unavailable(self):
        self.store.db.execute('DROP TABLE analysis_queue');self.store.db.commit()
        self.assertFalse(self.data()['queue_available']);self.assertIn('unavailable',self.text())
    def test_result_fifo_cannot_block_collection(self):
        self.populate();path=pathlib.Path(self.tmp.name)/('0'*24+'-v1.json');os.mkfifo(path)
        original=os.open
        def checked(path,flags,*args,**kwargs):
            if str(path).endswith('-v1.json'):self.assertTrue(flags & os.O_NONBLOCK)
            return original(path,flags,*args,**kwargs)
        with patch.object(agent.os,'open',side_effect=checked):self.engine.tick()
        self.assertEqual(self.store.db.execute('SELECT status FROM cases').fetchone()[0],'analysis_error')

if __name__=='__main__':unittest.main()
