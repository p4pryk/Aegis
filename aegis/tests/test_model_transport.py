import http.server
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch

import ai_worker


class ModelTransport(unittest.TestCase):
    def row(self):
        return {'id':'fixture','kind':'fixture','version':1,
                'evidence_json':json.dumps({'events':[],'allowed_actions':[]})}

    def test_invalid_endpoint_fails_before_managed_identity_token_is_requested(self):
        endpoints=('http://example.invalid','https://user:pass@example.invalid',
                   'https://example.invalid/?token=value','https://example.invalid/#fragment',
                   'https://example.invalid:bad','https://example.invalid\n.attacker.invalid')
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint),patch.object(ai_worker,'token') as token,patch.object(ai_worker,'open_model') as send:
                with self.assertRaises(ValueError):ai_worker.analyze(self.row(),{'endpoint':endpoint,'deployment':'test'})
                token.assert_not_called();send.assert_not_called()

    def test_exact_configured_host_scope_is_checked_before_token(self):
        config={'endpoint':'https://example.invalid','deployment':'test','allowed_hosts':['other.invalid']}
        with patch.object(ai_worker,'token') as token,self.assertRaises(ValueError):ai_worker.analyze(self.row(),config)
        token.assert_not_called()
        self.assertEqual(ai_worker.model_endpoint(dict(config,allowed_hosts=['EXAMPLE.INVALID'])),'https://example.invalid')
        for hosts in ([],['*.invalid'],['example.invalid',''],['example.invalid']*9,'example.invalid'):
            with self.subTest(hosts=hosts),self.assertRaises(ValueError):ai_worker.model_endpoint(dict(config,allowed_hosts=hosts))

    @unittest.skipUnless(shutil.which('openssl'),'OpenSSL is required for local TLS test')
    def test_real_tls_request_succeeds_and_cross_host_redirect_never_receives_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);key=root/'key.pem';cert=root/'cert.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
                            '-out',str(cert),'-days','1','-subj','/CN=localhost',
                            '-addext','subjectAltName=DNS:localhost'],capture_output=True,check=True,timeout=30)
            seen={'origin':[],'destination':[]};mode={'redirect':False};destination=None
            class Destination(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    seen['destination'].append(self.headers.get('Authorization'));self.send_response(200);self.end_headers()
                def log_message(self,*args):pass
            class Origin(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    seen['origin'].append(self.headers.get('Authorization'))
                    self.rfile.read(int(self.headers.get('Content-Length','0')))
                    if mode['redirect']:
                        self.send_response(302);self.send_header('Location',f'http://127.0.0.1:{destination.server_port}/leak');self.end_headers();return
                    body={'choices':[{'message':{'content':json.dumps({'summary':'Fixture','uncertainty':'Test',
                          'next_step':'Review','attack':False,'confidence':.1,'evidence_ids':[], 'proposed_action_ids':[]})}}]}
                    self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(body).encode())
                def log_message(self,*args):pass
            destination=http.server.HTTPServer(('127.0.0.1',0),Destination)
            origin=http.server.HTTPServer(('127.0.0.1',0),Origin)
            server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_context.load_cert_chain(cert,key)
            origin.socket=server_context.wrap_socket(origin.socket,server_side=True)
            threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (destination,origin)]
            for thread in threads:thread.start()
            try:
                context=ssl.create_default_context(cafile=str(cert))
                cfg={'endpoint':f'https://localhost:{origin.server_port}','deployment':'fixture','allowed_hosts':['localhost']}
                with patch.object(ai_worker,'token',return_value='fake-test-token'),patch.object(ssl,'_create_default_https_context',return_value=context),patch.dict(os.environ,{'HTTPS_PROXY':'http://127.0.0.1:9','NO_PROXY':''}):
                    self.assertFalse(ai_worker.analyze(self.row(),cfg)['analysis']['attack'])
                    mode['redirect']=True
                    with self.assertRaises(urllib.error.HTTPError) as error:ai_worker.analyze(self.row(),cfg)
                self.assertEqual(error.exception.code,302)
                error.exception.close()
                self.assertEqual(seen['origin'],['Bearer fake-test-token']*2)
                self.assertEqual(seen['destination'],[])
            finally:
                for server in (origin,destination):server.shutdown();server.server_close()
                for thread in threads:thread.join(timeout=5)


if __name__=='__main__':unittest.main()
