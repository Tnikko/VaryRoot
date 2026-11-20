"""Host-only DeepSeek proposal calls. Never mount this module or its key into roles."""
import argparse
import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from prepare_model import canonical


def build_request(lock,messages):
    return {'model':lock['model'],'messages':messages,'thinking':lock['thinking'],
            'reasoning_effort':lock['reasoning_effort'],'max_tokens':lock['max_tokens'],
            'top_p':lock['top_p'],'response_format':lock['response_format'],'stream':False}


def parse_response(response):
    try:
        choice,=response['choices']
        finish=choice['finish_reason']
        message=choice['message']
        if finish=='length': return {'status':'proposal_defect','reason':'truncated'}
        if finish!='stop' or message.get('tool_calls'): return {'status':'proposal_defect','reason':'unexpected_finish_or_tool'}
        content=message.get('content')
        if not isinstance(content,str) or not content.strip(): return {'status':'proposal_defect','reason':'blank_content'}
        try: parsed=json.loads(content)
        except (ValueError,TypeError): return {'status':'proposal_defect','reason':'invalid_json'}
        if not isinstance(parsed,dict) or not isinstance(parsed.get('proposals'),list):
            return {'status':'proposal_defect','reason':'invalid_envelope'}
        return {'status':'valid_output','reason':None,'proposal_count':len(parsed['proposals'])}
    except (KeyError,ValueError,TypeError):
        return {'status':'proposal_defect','reason':'invalid_response_shape'}


def write_once(path,raw):
    path=Path(path)
    if path.exists(): raise FileExistsError(path)
    temp=path.with_name('.'+path.name+'.tmp')
    with temp.open('xb') as file:
        file.write(raw)
        file.flush();os.fsync(file.fileno())
    os.replace(temp,path)


def call(project,index,endpoint):
    project=Path(project)
    out=project/'runs/step3-model-intake/out'
    if index not in (1,2,3): raise ValueError('only three predeclared calls')
    raw_file=out/f'model-{index:02d}.response.json'
    meta_file=out/f'model-{index:02d}.meta.json'
    if raw_file.exists() or meta_file.exists(): raise FileExistsError('call already recorded')
    key_path=Path(os.environ['VARYROOT_LLM_KEY_FILE']).resolve(strict=True)
    if key_path.is_relative_to(project) or stat.S_IMODE(key_path.stat().st_mode)&0o077:
        raise PermissionError('key must be private and outside project')
    key=key_path.read_text().strip()
    if not key.startswith('sk-') or '\n' in key: raise ValueError('invalid key file shape')
    if endpoint!='https://api.deepseek.com' and not (endpoint=='http://127.0.0.1:17901' and
             os.environ.get('VARYROOT_ALLOW_LOCAL_BRIDGE')=='1'):
        raise ValueError('unapproved API endpoint')
    lock=json.loads((out/'run-lock.json').read_bytes())
    messages=json.loads((out/'prompt.json').read_bytes())
    if hashlib.sha256(canonical(messages)).hexdigest()!=lock['prompt_sha256']:
        raise ValueError('prompt lock mismatch')
    request=build_request(lock,messages)
    request_bytes=canonical(request)
    write_once(out/f'model-{index:02d}.request.json',request_bytes)
    url=endpoint+'/chat/completions'
    req=urllib.request.Request(url,data=request_bytes,headers={'Authorization':'Bearer '+key,
                               'Content-Type':'application/json','Accept':'application/json'},method='POST')
    start=datetime.now(timezone.utc).isoformat()
    t0=time.monotonic()
    try:
        with urllib.request.urlopen(req,timeout=360) as response:
            raw=response.read()
            status=response.status
            egress=response.headers.get('X-Varyroot-Egress','direct')
    except urllib.error.HTTPError as error:
        raw=error.read();status=error.code;egress=error.headers.get('X-Varyroot-Egress','direct')
    except Exception as error:
        meta={'index':index,'start_utc':start,'elapsed_s':round(time.monotonic()-t0,3),
              'status':'infra_failure','error_type':type(error).__name__,'endpoint':endpoint,
              'request_sha256':hashlib.sha256(request_bytes).hexdigest(),'auto_retry':False}
        write_once(meta_file,canonical(meta))
        return meta
    write_once(raw_file,raw)
    info=json.loads(raw) if status==200 else None
    classification=parse_response(info) if info is not None else {'status':'http_failure','reason':'http_'+str(status)}
    usage=info.get('usage',{}) if info else {}
    hit=usage.get('prompt_cache_hit_tokens',0) or 0
    miss=usage.get('prompt_cache_miss_tokens',0) or 0
    out_tokens=usage.get('completion_tokens',0) or 0
    meta={'index':index,'start_utc':start,'elapsed_s':round(time.monotonic()-t0,3),
          'http_status':status,'endpoint':endpoint,'egress':egress,
          'request_sha256':hashlib.sha256(request_bytes).hexdigest(),
          'response_sha256':hashlib.sha256(raw).hexdigest(),
          'response_id':info.get('id') if info else None,
          'response_model':info.get('model') if info else None,
          'system_fingerprint':info.get('system_fingerprint') if info else None,
          'finish_reason':info['choices'][0].get('finish_reason') if info and info.get('choices') else None,
          'usage':usage,'estimated_cost_usd_range':{
              'off_peak':round((hit*.003+miss*.15+out_tokens*.6)/1_000_000,8),
              'peak':round((hit*.006+miss*.3+out_tokens*1.2)/1_000_000,8)},
          'auto_retry':False,**classification}
    write_once(meta_file,canonical(meta))
    return meta

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('index',type=int)
    parser.add_argument('--endpoint',default='https://api.deepseek.com')
    args=parser.parse_args()
    print(json.dumps(call(Path(__file__).resolve().parents[3],args.index,args.endpoint),ensure_ascii=False))
