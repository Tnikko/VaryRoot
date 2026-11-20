"""Read only the declared candidate files, then parse with the locked Clang 18 role."""
import hashlib
import importlib.util
import json
import tarfile
from pathlib import Path

I=Path('/input'); O=Path('/output'); W=Path('/tmp')
spec=importlib.util.spec_from_file_location('openldap_role',I/'openldap_role.py')
role=importlib.util.module_from_spec(spec);spec.loader.exec_module(role)
for name,folder in [('openldap-include.tar.gz','ldap'),('ubuntu24-libc-headers.tar.gz','sys')]:
    with tarfile.open(I/name) as archive:
        archive.extractall(W/folder,filter=lambda member,path: tarfile.data_filter(member,path)
                           if member.isfile() or member.isdir() else None)
def local_span(node):
    loc=node['range']
    begin=loc['begin'].get('expansionLoc',loc['begin'])
    end=loc['end'].get('expansionLoc',loc['end'])
    return [begin['offset'],end['offset']+end['tokLen']]

def local_text(source,node):
    a,b=local_span(node)
    return source[a:b].decode()


def goto_exits(walk, children, branch):
    # Only a branch consisting of one unconditional jump to a return is proved here.
    if branch.get('kind') == 'CompoundStmt' and len(children(branch)) == 1:
        branch = children(branch)[0]
    target_id = branch.get('targetLabelDeclId')
    if branch.get('kind') != 'GotoStmt' or not target_id:
        return False
    labels = [node for node, _, _ in walk if node.get('kind') == 'LabelStmt' and node.get('declId') == target_id]
    if len(labels) != 1 or len(children(labels[0])) != 1:
        return False
    destination = children(labels[0])[0]
    return destination.get('kind') == 'ReturnStmt' and all(
        node.get('kind') == 'IntegerLiteral' for node in children(destination))

rows={}
for case in json.loads((I/'cases.json').read_bytes())['cases']:
    name=case['id'];path=I/case['path'];source=path.read_bytes()
    item={'source_sha256':hashlib.sha256(source).hexdigest()}
    args=role.clang_args(path,W,W/'ldap',W/'sys',full=False)
    try:
        tree,ast_sha=role.compile_and_parse(args,'ldap_recv_slice')
    except Exception as error:
        item.update(status='compile_failure',diagnostic=str(error)[-900:])
        rows[name]=item;continue
    item['ast_sha256']=ast_sha
    try:
        analysis=role.analyze_tree(tree,source)
        outer=tree
        for index in analysis['outer_for_path']: outer=role.children(outer)[index]
        condition=role.children(outer)[2]
        outer_condition=local_text(source,condition)
        before=[]
        base=tuple(analysis['outer_for_path'])
        target_start=analysis['target_span'][0]
        tree_nodes=list(role.walk(tree))
        for node,node_path,_ in tree_nodes:
            if (node.get('kind')!='IfStmt' or tuple(node_path[:len(base)])!=base
                    or local_span(node)[0]>=target_start):
                continue
            kids=role.children(node)
            if len(kids)<2: continue
            cond=kids[0]
            before.append({'path':list(node_path),'condition':local_text(source,cond),
                           'condition_span':local_span(cond),'span':local_span(node),
                           'then_kinds':[n.get('kind') for n,_,_ in role.walk(kids[1])],
                           'goto_exits':goto_exits(tree_nodes,role.children,kids[1]),
                           'contains_target':tuple(analysis['inner_for_path'][:len(node_path)])==tuple(node_path),
                           'direct_child':tuple(node_path[:-1])==base+(4,)})
        item.update(status='valid',analysis=analysis,outer_condition=outer_condition,
                    pretarget_ifs=before,clang_version=role.VERSION)
    except Exception as error:
        item.update(status='unsupported_shape',diagnostic=str(error)[-900:])
    rows[name]=item
(O/'ast-results.json').write_text(json.dumps(rows,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
