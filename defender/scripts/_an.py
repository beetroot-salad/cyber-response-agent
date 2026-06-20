import json,re,collections,sys,os
rd=sys.argv[1]
rows=[json.loads(l) for l in open(f'{rd}/llm_requests.jsonl')]
resp=[d for d in rows if d.get('kind')=='response' and (d.get('agent_id') or '').startswith('gather:')]
callmeta={}
for d in rows:
    if d.get('kind')=='response':
        for p in d['message'].get('parts',[]):
            if p.get('part_kind')=='tool-call':
                a=p.get('args',{})
                callmeta[p.get('tool_call_id')]=('read',a.get('path','')) if p.get('tool_name')=='read_file' else ('bash',a.get('command',''))
retsize={}; maxret=(0,'')
for d in rows:
    if d.get('kind')=='request':
        for p in d['message'].get('parts',[]):
            if p.get('part_kind')=='tool-return':
                c=p.get('content',''); c=c if isinstance(c,str) else json.dumps(c)
                retsize[p.get('tool_call_id')]=len(c)
                typ,arg=callmeta.get(p.get('tool_call_id'),('?',''))
                if len(c)>maxret[0]: maxret=(len(c),arg[:90])
peak=0; buckets=collections.Counter(); batch=0; label=0; subreads=[]; fullrec=[]
for d in resp:
    u=d['message'].get('usage',{}) or {}
    peak=max(peak,(u.get('cache_read_tokens',0)or 0)+(u.get('input_tokens',0)or 0))
    for p in d['message'].get('parts',[]):
        if p.get('part_kind')!='tool-call': continue
        tn=p.get('tool_name'); a=p.get('args',{})
        if tn=='read_file':
            path=a.get('path','')
            m=re.search(r'gather/(validate|measure|lead-kinds)\.md$',path)
            if m: subreads.append(m.group(1)); buckets['read:subfile']+=1
            elif re.search(r'skills/[a-z-]+/(SKILL|execution)',path): buckets['read:system-skill']+=1
            elif 'queries/' in path: buckets['read:template']+=1
            else: buckets['read:other']+=1
        else:
            cmd=a.get('command','')
            if 'record-summary' in cmd:
                if '--batch' in cmd: batch+=1; buckets['summary:batch']+=1
                else: label+=1; buckets['summary:label']+=1
            elif re.search(r'defender-(elastic|cmdb|identity|ticket|change-mgmt|threat-intel|host-state)\b',cmd):
                buckets['query:adapter']+=1
            elif 'gather_raw' in cmd or cmd.strip().startswith('jq') or '.hits' in cmd:
                buckets['flail:jq']+=1
                if 'select(' in cmd and not re.search(r'length|unique|group_by|min|max|\badd\b|\.\[[0-9]|@tsv|\bkeys\b|count|sort_by|to_entries',cmd):
                    rs=retsize.get(p.get('tool_call_id'))
                    fullrec.append((rs//4 if rs else None, cmd[:100].replace(chr(10),' ')))
            elif cmd.split()[0:1] and cmd.split()[0] in ('ls','find'): buckets['catalog:ls']+=1
            else: buckets['other']+=1
# payload size
import glob
psz=max((os.path.getsize(p) for p in glob.glob(f'{rd}/gather_raw/l-001/*.json')),default=0)
print(f'{os.path.basename(rd)}: gather_responses={len(resp)} cap_hit={len(resp)>=40} peak_ctx~{peak:,} payload={psz/1e6:.1f}MB')
print(f'   biggest single tool-return ~{maxret[0]//4:,}t from: {maxret[1]}')
print(f'   --batch={batch}  --label(per-dim)={label}  subfile_reads={subreads or 0}')
print(f'   FULL-RECORD jq (select, no reducer): {len(fullrec)}', '  <-- fix held' if not fullrec else '')
for tok,c in fullrec[:3]: print(f'       ~{tok}t  {c}')
print('   tool-call buckets:', dict(buckets.most_common()))
gs=f'{rd}/gather_summaries/l-001.md'
if os.path.exists(gs):
    t=open(gs).read()
    cap='hit its request limit' in t
    print(f'   OUTCOME: {"CAP-STUB (incomplete)" if cap else "REAL SUMMARY"}  ({len(t)}c)')
