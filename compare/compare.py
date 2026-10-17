"""Compare eight MUSUBI core fields over every vector in sealed/vectors.
Usage: compare.py ROOT [OUTPUT_NAME]. Writes compare/OUTPUT_NAME (default comparison.json).
Exit 1 for any disagreement, unassessed field or missing output; 0 only on full agreement."""
from pathlib import Path
import json,sys

FIELDS=['contract_sha256','verdict','status','bond_outcome','deviation_codes','underspecified_reasons','event_set','dispositions']
SETS={'deviation_codes','underspecified_reasons'}

def equal(a,b):
 if type(a) is not type(b):return False
 if isinstance(a,dict):return set(a)==set(b) and all(equal(a[k],b[k]) for k in a)
 if isinstance(a,list):return len(a)==len(b) and all(equal(x,y) for x,y in zip(a,b))
 return a==b

def compare(expected,actual):
 diffs=[]
 for f in FIELDS:
  if f not in expected or f not in actual:
   diffs.append({'field':f,'kind':'MISSING_FIELD'});continue
  e,a=expected[f],actual[f]
  if isinstance(a,str) and a.startswith('UNASSESSED'):
   diffs.append({'field':f,'kind':'UNASSESSED','expected':e,'actual':a});continue
  if f in SETS:
   same=isinstance(e,list) and isinstance(a,list) and all(type(x) is str for x in e+a) and set(e)==set(a)
  else:same=equal(e,a)
  if not same:diffs.append({'field':f,'kind':'DISAGREE','expected':e,'actual':a})
 return diffs

def main(root,name='comparison.json'):
 rows=[]
 for vector in sorted((root/'sealed/vectors').iterdir()):
  if not vector.is_dir():continue
  expected=json.loads((vector/'expected.json').read_text())
  outp=root/'out'/(vector.name+'.json')
  if not outp.exists():
   rows.append({'vector':vector.name,'all_eight_agree':False,'diffs':[{'kind':'MISSING_OUTPUT'}]});continue
  actual=json.loads(outp.read_text())
  diffs=compare(expected,actual)
  rows.append({'vector':vector.name,'all_eight_agree':not diffs,'diffs':diffs})
 (root/'compare').mkdir(exist_ok=True)
 (root/'compare'/name).write_text(json.dumps(rows,indent=2)+'\n')
 agreed=sum(r['all_eight_agree'] for r in rows)
 unass=sum(any(d.get('kind')=='UNASSESSED' for d in r['diffs']) for r in rows)
 print(f'vectors {len(rows)}, all eight agree {agreed}, with an UNASSESSED field {unass}, disagree {len(rows)-agreed-unass}')
 for row in rows:
  for diff in row['diffs']:print(row['vector'],json.dumps(diff,sort_keys=True))
 return 0 if rows and agreed==len(rows) else 1

if __name__=='__main__':raise SystemExit(main(Path(sys.argv[1]),*sys.argv[2:3]))
