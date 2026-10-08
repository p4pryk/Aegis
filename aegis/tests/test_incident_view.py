import json,pathlib,subprocess,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import console
from incident_view import timeline

class IncidentView(unittest.TestCase):
    def case(self):
        events=[{'event_id':'later','event_time':20,'kind':'security_file_change','subject':'/etc/group','details':{'path':'/etc/group','pid':20,'session':'42','auid':'1002','boot_id':'boot'}},
                {'event_id':'first','event_time':10,'kind':'ssh_session_open','subject':'actor','details':{'user':'actor','session':'42','ip':'198.51.100.9'}}]
        return {'id':'case123','version':2,'kind':'host_change','status':'insufficient_evidence','evidence_json':json.dumps({'events':events,'edges':[{'from':'first','to':'later','relation':'exact_audit_session_attribution_not_causal'}],'allowed_actions':[],'policy':{}}),'analysis_json':json.dumps({'summary':'Group attributes changed.','uncertainty':'Authorization unknown.','next_step':'Review this change.','attack':False,'confidence':.7,'language':'en'}),'result_json':'[]'}

    def test_chronology_attribution_model_and_gate_are_separate(self):
        text='\n'.join(t for t,_ in timeline(self.case()))
        self.assertLess(text.index('ssh_session_open'),text.index('security_file_change'))
        for needle in ('#1 -> #2 [ATTRIBUTION]','not a calibrated probability','Authorization unknown','No response authorized','Review-only evidence'):self.assertIn(needle,text)
        self.assertNotIn('VERIFIED LINK',text)

    def test_unlinked_evidence_and_missing_chain_are_explained(self):
        case=self.case();case['kind']='app_sql_login';e=json.loads(case['evidence_json']);e['edges']=[];case['evidence_json']=json.dumps(e)
        text='\n'.join(t for t,_ in timeline(case))
        self.assertIn('Events without a recorded link: #1, #2',text);self.assertIn('kernel-confirmed consequence',text)

    def test_terminal_controls_and_application_tokens_are_not_rendered(self):
        case=self.case();case['analysis_json']=json.dumps({'summary':'\x1b[2J injected '+ 'a'*32,'confidence':.9})
        text='\n'.join(console.chain_lines({'cases':[case]},90))
        self.assertNotIn('\x1b',text);self.assertNotIn('a'*32,text)

    def test_chain_scroll_keeps_logo_and_frame_bounds(self):
        data={'cases':[self.case()]}
        for width,height in ((120,32),(60,24),(31,11)):
            a=console.render(data,width,height,mode='chain',case_id='case123',offset=0)
            b=console.render(data,width,height,mode='chain',case_id='case123',offset=15)
            self.assertEqual(len(a),height);self.assertEqual(len(b),height)
            self.assertTrue(all(console.cells(line)<=width for line in a+b))
            self.assertEqual(a[0],b[0])

    def test_full_snapshot_case_prints_untruncated_details(self):
        with tempfile.TemporaryDirectory() as directory:
            p=pathlib.Path(directory)/'fixture.json';p.write_text(json.dumps({'cases':[self.case()]}))
            text=subprocess.check_output([sys.executable,console.__file__,'--data-file',str(p),'--case','case123','--snapshot','--height','12','--width','120'],text=True)
            self.assertIn('RECORDED FACTS',text);self.assertIn('Recorded state: insufficient_evidence',text)

    def test_unavailable_selection_does_not_silently_show_another_case(self):
        text='\n'.join(console.chain_lines({'cases':[self.case()]},90,'missing'))
        self.assertIn('not available',text);self.assertNotIn('Group attributes',text)
