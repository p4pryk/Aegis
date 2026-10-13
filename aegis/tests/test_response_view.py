import json,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import console,response_view,rollback

class ResponseView(unittest.TestCase):
    def row(self,state='contained',**kw):
        return dict(id='a'*32,time=10,action='block_ip',target='192.0.2.12',state=state,eligible=True,**kw)
    def test_projection_excludes_private_details_and_reasons(self):
        row=self.row(history=[{'state':'refused','reason':'SECRET','error':'ownership changed','time':15}],before={'shadow_hash':'SECRET'},token='SECRET')
        result=response_view.public_receipt(row)
        self.assertNotIn('SECRET',json.dumps(result));self.assertEqual(result['last_state'],'refused')
        self.assertEqual(result['updated_at'],15)
    def test_refusal_and_uncertainty_appear_until_restored(self):
        for state in ('prepared','forward_uncertain','undo_running','undo_uncertain','contained'):
            row=self.row(state,last_state='refused',error='ownership changed')
            text='\n'.join(response_view.history_lines({'responses':[row],'response_history_status':'AVAILABLE'},100,True))
            self.assertIn('REVIEW REQUIRED',text);self.assertIn('ownership changed',text)
        text='\n'.join(response_view.history_lines({'responses':[self.row('restored',last_state='refused')]},100,True))
        self.assertNotIn('REVIEW REQUIRED',text)
    def test_history_does_not_infer_expiry_or_current_protection(self):
        text='\n'.join(response_view.history_lines({'responses':[self.row(expires_at=1)]},110))
        self.assertIn('CONTAINED',text);self.assertNotIn('[EXPIRED]',text);self.assertIn('not a live host-state',text)
    def test_missing_history_is_visible(self):
        self.assertEqual(response_view.read_receipts('/nonexistent/db')['response_history_status'],'UNAVAILABLE')
        self.assertIn('unavailable','\n'.join(response_view.history_lines({},100,True)))
    def test_controls_redacted_and_frames_fit_scroll(self):
        data={'responses':[self.row(target_override='unused',error='\x1b[2J bad',last_state='refused')]*10}
        for mode in ('responses','review'):
            for width,height in ((120,40),(60,24),(31,11)):
                a=console.render(data,width,height,mode=mode);b=console.render(data,width,height,mode=mode,offset=6)
                self.assertEqual(len(a),height);self.assertEqual(a[:6],b[:6])
                self.assertTrue(all(console.cells(line)<=width for line in a+b));self.assertNotIn('\x1b','\n'.join(a))
    def test_private_receipt_updates_public_history(self):
        with tempfile.TemporaryDirectory() as directory:
            journal=rollback.Journal({'data_dir':directory})
            row=self.row(before={'shadow_hash':'SECRET'});journal.save(row)
            path=pathlib.Path(directory)/'response-history'/(row['id']+'.json')
            self.assertEqual(path.stat().st_mtime,10);self.assertEqual(path.stat().st_mode&0o777,0o644);self.assertNotIn('SECRET',path.read_text())
            row['state']='restored';journal.save(row);self.assertEqual(json.loads(path.read_text())['state'],'restored')
    def test_analysis_errors_have_evidence_and_next_step(self):
        data={'review_cases':[{'id':'case-old','status':'analysis_error','evidence_json':'{"events":[{},{}],"edges":[{}]}','review_details':'{"error":"analysis deadline exceeded"}'}]}
        text='\n'.join(response_view.history_lines(data,120,True))
        for value in ('case-old','2 events / 1 links','deadline exceeded','--case case-old'):self.assertIn(value,text)
    def test_review_query_includes_errors_outside_recent_cases_and_is_readonly(self):
        import agent
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory)
            store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
            try:
                for n in range(45):
                    store.db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(str(n),n,n,'test','host',1,'analysis_error' if n==0 else 'observing','{}','{}','[]'))
                store.db.execute('INSERT INTO case_status_history VALUES (?,?,?,?)',('0','analysis_error',1,'{"error":"deadline exceeded"}'));store.db.commit()
                before=store.db.total_changes
                snapshot=console.read_snapshot(pathlib.Path(directory)/'incidents.db')
                self.assertEqual(len(snapshot['cases']),40);self.assertEqual(snapshot['review_cases'][0]['id'],'0')
                self.assertEqual(store.db.total_changes,before)
                self.assertIn('deadline exceeded','\n'.join(response_view.history_lines(snapshot,100,True)))
            finally:store.db.close()

    def test_service_umask_does_not_hide_public_projection(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            previous=os.umask(0o077)
            try:
                journal=rollback.Journal({'data_dir':directory});journal.save(self.row())
            finally:os.umask(previous)
            self.assertEqual((pathlib.Path(directory)/'response-history').stat().st_mode&0o777,0o755)
            self.assertEqual(journal.root.stat().st_mode&0o777,0o700)
