"""Compare eight MUSUBI core fields. Exit 1 for any disagreement or unassessed field."""
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

def main(root):
 rows=[]
 for vector in sorted((root/'sealed/vectors').iterdir()):
  if not vector.is_dir():continue
  expected=json.loads((vector/'expected.json').read_text())
  actual=json.loads((root/'out'/(vector.name+'.json')).read_text())
  diffs=compare(expected,actual)
  rows.append({'vector':vector.name,'all_eight_agree':not diffs,'diffs':diffs})
 (root/'compare').mkdir(exist_ok=True)
 (root/'compare/comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
 agreed=sum(r['all_eight_agree'] for r in rows)
 print(f'vectors {len(rows)}, all eight agree {agreed}')
 for row in rows:
  for diff in row['diffs']:print(row['vector'],json.dumps(diff,sort_keys=True))
 return 0 if rows and agreed==len(rows) else 1

if __name__=='__main__':raise SystemExit(main(Path(sys.argv[1])))
