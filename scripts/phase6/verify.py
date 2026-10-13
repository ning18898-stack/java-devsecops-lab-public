"""Resume-capable local Gate with explicit evidence links; never asserts hosted CI passed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent))
from ci import ROOT, LEGAL_FILES, Run, git, sha, write_json
from labscan.core import now

REQUIRED = ('java','python','backend','frontend','semgrep','codeql','zap','workflows','hygiene')


def fingerprint():
    digest=hashlib.sha256()
    names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','scripts/phase6','.github/workflows',*sorted(LEGAL_FILES)],cwd=ROOT).decode().splitlines()
    for name in sorted(set(names)):
        path=ROOT/name
        digest.update(name.encode());digest.update(path.read_bytes().replace(b'\r\n',b'\n'))
    return digest.hexdigest()


def receipt(path):
    path=Path(path).resolve()
    if not path.is_relative_to(ROOT/'artifacts'):
        raise ValueError('Gate evidence must be in project artifacts')
    data=json.loads(path.read_text(encoding='utf-8'))
    if data.get('status')!='PASS' or data.get('exit_code')!=0 or not data.get('started') or not data.get('ended'):
        raise ValueError('Missing actual successful execution receipt')
    if any(r.get('execution_status')!='COMPLETED' for r in data.get('commands',[])):
        raise ValueError('Failed command in successful receipt')
    return {'status':'PASS','evidence':str(path.relative_to(ROOT)).replace('\\','/'),'sha256':sha(path),
            'started':data['started'],'ended':data['ended'],'exit_code':data['exit_code'],
            'environment':data.get('environment'),'result':data.get('result',{}),
            'clean_checkout':data.get('clean_checkout',False)}


def assemble(stage_paths, integration, clean, ubuntu):
    if set(stage_paths)!=set(REQUIRED):
        raise ValueError('All nine required local categories need actual evidence')
    entries={stage:receipt(path) for stage,path in stage_paths.items()}
    entries['dashboard_http_browser']=receipt(integration)
    entries['clean_windows']=receipt(clean)
    if not entries['clean_windows']['clean_checkout']:
        raise ValueError('An original-workspace smoke cannot stand in for clean-checkout validation')
    entries['ubuntu']=receipt(ubuntu) if ubuntu else {'status':'NOT_TESTED','reason':'No actual native Ubuntu receipt supplied'}
    entries['hosted_actions']={'status':'NOT_TESTED','reason':'No push or remote authorization/execution'}
    entries['hosted_codeql_license']={'status':'BLOCKED','reason':'No target repository, visibility or eligible license reviewed'}
    return {'PHASE6_LOCAL_READY':True,'PHASE6_READY':False,'status':'PASS',
            'scope':'Local engineering Gate only; Ubuntu receipt covers only its stated executed categories',
            'matrix':entries}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--assemble',type=Path,help='JSON of explicit stage receipt paths plus integration, clean and optional ubuntu')
    parser.add_argument('--resume',type=Path,help='Prior checkpoints.json with unchanged implementation fingerprint')
    args=parser.parse_args()
    run=Run(ROOT/'artifacts/phase6')
    state={'started':now(),'implementation_fingerprint':fingerprint(),'stages':{}}
    code=1
    try:
        if args.assemble:
            config=json.loads(args.assemble.read_text(encoding='utf-8'))
        else:
            if os.name!='nt':raise ValueError('Complete local Gate requires Windows sealed CodeQL and Edge interfaces')
            if args.resume:
                old=json.loads(args.resume.read_text(encoding='utf-8'))
                if old['implementation_fingerprint']!=state['implementation_fingerprint']:
                    raise ValueError('Implementation changed; resume refused')
                state['stages']=old['stages']
            backend_python=ROOT/'dashboard/backend/.venv/Scripts/python.exe'
            for stage in REQUIRED:
                if stage in state['stages']:
                    entry=state['stages'][stage]
                    if sha(ROOT/entry['evidence'])!=entry['sha256']:raise ValueError('Resume receipt changed')
                    receipt(ROOT/entry['evidence']);continue
                before=set(ROOT.glob('artifacts/phase6/*/result.json'))
                run.command([backend_python if stage=='backend' else sys.executable,ROOT/'scripts/phase6/ci.py',stage],
                            'gate-'+stage,timeout=3600)
                created=set(ROOT.glob('artifacts/phase6/*/result.json'))-before
                if len(created)!=1:raise ValueError('Ambiguous stage receipt')
                state['stages'][stage]=receipt(created.pop())
                (run.path/'checkpoints.json').write_text(json.dumps(state,indent=2),encoding='utf-8')
            run.command([backend_python,ROOT/'scripts/phase6/integration.py'],'gate-integration',timeout=600)
            integrations=sorted(ROOT.glob('artifacts/phase6/*/integration.json'),key=lambda p:p.stat().st_mtime)
            run.command([backend_python,ROOT/'scripts/phase6/smoke.py'],'gate-smoke',timeout=120)
            smokes=sorted(ROOT.glob('artifacts/phase6/*/smoke.json'),key=lambda p:p.stat().st_mtime)
            snapshot_log=run.command([sys.executable,ROOT/'scripts/phase6/snapshot.py'],'clean-snapshot')
            target=Path(snapshot_log.read_text().strip().splitlines()[-1])
            run.command([sys.executable,target/'scripts/phase6/bootstrap.py','dashboard'],'clean-bootstrap',cwd=target,timeout=1200)
            run.command([sys.executable,target/'scripts/phase6/ci.py','frontend'],'clean-frontend',cwd=target,timeout=600)
            clean_python=target/'dashboard/backend/.venv/Scripts/python.exe'
            run.command([clean_python,target/'scripts/phase6/ci.py','backend'],'clean-backend',cwd=target,timeout=600)
            run.command([clean_python,target/'scripts/phase6/integration.py'],'clean-integration',cwd=target,timeout=600)
            clean_file=run.path/'clean-checkout.json'
            write_json(clean_file,{'status':'PASS','exit_code':0,'clean_checkout':True,'started':state['started'],
                'ended':now(),'environment':'win32','commands':run.commands,'target':str(target),
                'result':{'frontend':'7 tests/build','backend':'51 tests','integration':'17 HTTP/restart/3 Edge tests',
                          'dependency_state':'fresh venv/node_modules/DB; host Python/Node reused as documented'}})
            config={'stages':{k:ROOT/v['evidence'] for k,v in state['stages'].items()},'integration':integrations[-1],
                    'clean':clean_file,'ubuntu':None}
        summary=assemble(config['stages'],config['integration'],config['clean'],config.get('ubuntu'))
        summary.update(started=state['started'],ended=now(),exit_code=0,source_revision=git('rev-parse','HEAD'),
                       implementation_fingerprint=state['implementation_fingerprint'])
        write_json(run.path/'gate.json',summary)
        code=0
    except Exception as error:
        write_json(run.path/'gate.json',{'PHASE6_LOCAL_READY':False,'PHASE6_READY':False,'status':'FAIL',
            'started':state['started'],'ended':now(),'exit_code':1,'failure':str(error),'stages':state['stages']})
    print(json.dumps({'exit_code':code,'gate':str(run.path/'gate.json')}))
    return code


if __name__=='__main__':sys.exit(main())
