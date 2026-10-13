"""Portable actual HTTP import/restart check using independent storage and reviewed input."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).parent))
from ci import ROOT, Run, IDS, materialize, write_json, git
from labscan.core import now


def main():
    materialize()
    run = Run(ROOT / "artifacts/phase6")
    summary = {"status":"FAIL", "started":now(), "run_id":run.id,
               "environment":sys.platform, "python_version":sys.version.split()[0], "source_revision":git("rev-parse","HEAD")}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1",18765))
    env = dict(os.environ, DASHBOARD_DB=str(run.path/"smoke.sqlite3"), DASHBOARD_IMPORT_ROOT=str(ROOT/"artifacts/phase4"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    handles = []
    calls = []
    token = None
    def request(method, path, body=None, expected=200):
        headers = {"Content-Type":"application/json"}
        if token:
            headers['x-dashboard-token'] = token
        req = urllib.request.Request('http://127.0.0.1:18765/api'+path,
            data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        try:
            response = opener.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, data = response.status, json.loads(response.read())
        calls.append({"method":method,"path":path,"status":status,"timestamp":now()})
        if status != expected:
            raise AssertionError('Unexpected HTTP status')
        return data
    def start():
        handle = (run.path/f'service-{len(handles)}.log').open('w',encoding='utf-8')
        handles.append(handle)
        proc = subprocess.Popen([sys.executable,str(ROOT/'dashboard/backend/serve.py'),'--port','18765'],
            cwd=ROOT,env=env,stdout=handle,stderr=handle,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError('Backend exited before startup')
            try:
                request('GET','/health')
                return proc
            except urllib.error.URLError:
                time.sleep(.1)
        proc.terminate();proc.wait(timeout=15)
        raise TimeoutError('Backend health timeout')
    code = 1
    try:
        process=start()
        assert request('GET','/summary')['runs']==0
        request('POST','/imports',{'run_id':IDS[0]},403)
        token=request('GET','/session')['write_token']
        assert request('POST','/imports',{'run_id':IDS[0]})['imported']
        assert not request('POST','/imports',{'run_id':IDS[0]})['imported']
        data=request('GET','/summary')
        assert data['observations']==5 and data['independent_vulnerability_count'] is None
        rows=request('GET','/findings')['items']; fid=rows[0]['id']
        detail=request('GET',f'/findings/{fid}')
        assert detail['observations'][0]['source_snippet']
        request('GET',f"/evidence/{detail['observations'][0]['evidence'][0]['id']}")
        request('POST',f'/findings/{fid}/status',{'status':'confirmed','version':detail['version'],'note':'Phase6 isolated HTTP persistence check; no new vulnerability or remediation assertion'})
        before=request('GET',f'/findings/{fid}')
        process.terminate();process.wait(timeout=15)
        process=start()
        after=request('GET',f'/findings/{fid}')
        assert before['history']==after['history'] and after['status']=='confirmed'
        summary.update(status='PASS',restart='PASS',actual_http_requests=len(calls),database='independent smoke.sqlite3',input_provenance='reviewed Phase4 historical derivative')
        code=0
    except Exception as error:
        summary['failure']=str(error)
    finally:
        if process and process.poll() is None:
            process.terminate();process.wait(timeout=15)
        for handle in handles:handle.close()
        summary.update(ended=now(),exit_code=code,calls=calls)
        write_json(run.path/'smoke.json',summary)
    print(json.dumps({"status":summary['status'],"run_id":run.id,"exit_code":code}))
    return code


if __name__=='__main__':
    sys.exit(main())
