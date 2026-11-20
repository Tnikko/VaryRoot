"""Export the accepted seed's public proposal inputs, without revealed case evidence."""
import hashlib
import json
from pathlib import Path
from varyroot.ledger import Ledger
from varyroot.openldap_qualification import artifact, RUN


def canonical(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()


def ref(row):
    return f"{row['id']}@{row['version']}"


def prepare(project):
    project=Path(project)
    db=Ledger(project/'runs/interface3-static/production-ledger')
    run=db.run(RUN)
    if run['state']!='seed_accepted' or db.seed_gate(RUN)['blockers']:
        raise ValueError('production seed not accepted')
    packet=db.seed_package(RUN)
    accepted=[e for e in db.events(RUN) if e['kind']=='seed_accepted']
    if len(accepted)!=1:
        raise ValueError('ambiguous acceptance')
    details=accepted[0]['detail']['detail']
    specs={ref(row['spec']):{'spec':row['spec'],'clauses':row['clauses']}
           for row in artifact(packet,'hypothesis_set')['specs']}
    surviving=details['surviving_explanations']
    if len(surviving)!=3 or set(surviving)!=set(specs):
        raise ValueError('survivor snapshot changed')
    skeletons={}
    target_refs={}
    for side in ('before','after'):
        item=artifact(packet,side+'_sources')
        view=item['views'][1]['target']
        snap=item['snapshots'][1]
        source=snap['files'][view['file']]
        start,end=view['byte_span']
        if source.encode()[start:end]!=b'bvals[i].bv_val':
            raise ValueError('wrong seed target')
        skeletons[side]=source
        target_refs[side]={'target_ref':view['target_ref']+'@1','sha256':hashlib.sha256(source.encode()).hexdigest(),
                           'byte_span':[start,end],'ast_path':view['ast_path']}
    contract_path=project/'runs/interface3-static/catalog/contract.json'
    contract=json.loads(contract_path.read_bytes())
    if contract['approval_status']!='approved' or contract['reference_commit']!=details['contract']['reference_commit']:
        raise ValueError('contract snapshot changed')
    return {'schema':1,'seed_run':RUN,'seed_package_sha256':packet['packet_sha'],
            'source_lock':packet['packet']['source_lock'],'contract':contract,
            'contract_sha256':hashlib.sha256(contract_path.read_bytes()).hexdigest(),
            'baseline':details['baseline_spec'],'models':{k:specs[k] for k in surviving},
            'skeletons':skeletons,'target_refs':target_refs,
            'scope':details['scope']['scope']}


def prompt(payload):
    system=("你是受控 C 代码对照案例的提案器。只输出一个 JSON 对象，键为 proposals；"
            "每个元素仅有 parent、factor、intent、source。source 是完整 C 翻译单元。"
            "不要生成 Fact、标签、规约预测、契约审批或任何工具调用。不得联网检索。")
    task=("根据给定的父版或修复版骨架，提议 4 至 6 个局部单因素 C 变体。"
          "每例必须选择 parent=before 或 after，并写清唯一变化因素。"
          "优先尝试判空后继续、故障路径退出、等价控制流改写、对象身份检查；"
          "保留 OpenLDAP 两次调用及其输出槽契约，保留内层循环条件首次 bvals[i].bv_val 目标。"
          "如果某种机制需要改变这些前提，仍可提出，但请明确 intent，准入器会独立拒收或标记超出形态。"
          "factor 用 rename、invalid_source、propagation、guard_contract、path_block_scope、"
          "control_flow_rewrite、sink_change 中的一个。只提供代码与意图，不给结论。")
    return [{'role':'system','content':system},
            {'role':'user','content':json.dumps({'task':task,'input':payload},ensure_ascii=False,sort_keys=True)}]


def write(project):
    project=Path(project)
    out=project/'runs/step3-model-intake/out'
    out.mkdir(parents=True,exist_ok=True)
    data=prepare(project)
    messages=prompt(data)
    (out/'proposal-input.json').write_bytes(canonical(data))
    (out/'prompt.json').write_bytes(canonical(messages))
    lock={'schema':1,'seed_run':RUN,'input_sha256':hashlib.sha256(canonical(data)).hexdigest(),
          'prompt_sha256':hashlib.sha256(canonical(messages)).hexdigest(),
          'api':'chat/completions','model':'deepseek-flash','thinking':{'type':'enabled'},
          'reasoning_effort':'high','max_tokens':32768,'top_p':1.0,
          'response_format':{'type':'json_object'},'tools':None,'temperature':None,
          'calls':3,'transport':'7server SSH reverse tunnel via Windows VPN 7900',
          'sources':['https://api-docs.deepseek.com/guides/thinking_mode/',
                     'https://api-docs.deepseek.com/api/create-chat-completion/',
                     'https://api-docs.deepseek.com/quick_start/pricing/']}
    (out/'run-lock.json').write_bytes(canonical(lock))
    return lock

if __name__=='__main__':
    print(json.dumps(write(Path(__file__).resolve().parents[3]),ensure_ascii=False))
