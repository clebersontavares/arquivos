import csv, hashlib, json, os, sqlite3, sys, threading, webbrowser, shutil
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
ROOT=Path(__file__).resolve().parent; BASE=ROOT.parent
LEGACY_DATA=BASE/'data'; LEGACY_DATA.mkdir(exist_ok=True)
if os.name=='nt' and os.environ.get('LOCALAPPDATA'):
 DATA=Path(os.environ['LOCALAPPDATA'])/'STW'/'BlockManagerAnalytics'
else:
 DATA=LEGACY_DATA
DATA.mkdir(parents=True,exist_ok=True); DB=DATA/'blockmanager-analytics.db'
LEGACY_DB=LEGACY_DATA/'blockmanager-analytics.db'
if not DB.exists() and LEGACY_DB.exists() and LEGACY_DB.resolve()!=DB.resolve(): shutil.copy2(LEGACY_DB,DB)
MEMORY_CACHE={}
def filter_signature(q):
 clean={}
 for k,v in sorted(q.items()):
  if k in ('page','page_size'):continue
  vals=[str(x).strip() for x in v if str(x).strip()!='']
  if vals:clean[k]=vals
 if 'from' not in clean:clean.pop('from_time',None)
 if 'to' not in clean:clean.pop('to_time',None)
 return json.dumps(clean,sort_keys=True,ensure_ascii=False,separators=(',',':'))
def current_generation(c=None):
 own=c is None; c=c or con()
 try:return int(c.execute("SELECT value FROM app_meta WHERE key='generation'").fetchone()[0])
 finally:
  if own:c.close()
def cache_key(scope,kind,q,generation=None):
 raw=scope+'|'+kind+'|'+filter_signature(q); return hashlib.sha256(raw.encode()).hexdigest(),generation
def cache_get(scope,kind,q):
 gen=current_generation(); key,_=cache_key(scope,kind,q,gen); mem=(gen,key)
 if mem in MEMORY_CACHE:return MEMORY_CACHE[mem]
 c=con()
 try:
  row=c.execute('SELECT payload_json FROM analytics_cache WHERE cache_key=? AND generation=?',(key,gen)).fetchone()
  if not row:return None
  data=json.loads(row[0]); MEMORY_CACHE[mem]=data; return data
 finally:c.close()
def cache_set(scope,kind,q,data):
 c=con()
 try:
  gen=current_generation(c); key,_=cache_key(scope,kind,q,gen)
  c.execute('INSERT OR REPLACE INTO analytics_cache(cache_key,scope,kind,filter_json,generation,payload_json,generated_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)',(key,scope,kind,filter_signature(q),gen,json.dumps(data,ensure_ascii=False,separators=(',',':'))));c.commit();MEMORY_CACHE[(gen,key)]=data
 finally:c.close()
def cache_clear():
 c=con()
 try:
  gen=current_generation(c)+1;c.execute("UPDATE app_meta SET value=? WHERE key='generation'",(str(gen),));c.execute('DELETE FROM analytics_cache');c.commit();MEMORY_CACHE.clear()
 finally:c.close()
SCHEMA='''PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS imports(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,file_name TEXT NOT NULL,file_date TEXT,file_size INTEGER NOT NULL,sha256 TEXT UNIQUE NOT NULL,imported_at TEXT DEFAULT CURRENT_TIMESTAMP,rows_accepted INTEGER DEFAULT 0,rows_rejected INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT OR IGNORE INTO app_meta(key,value) VALUES('generation','1');
CREATE TABLE IF NOT EXISTS analytics_cache(cache_key TEXT PRIMARY KEY,scope TEXT NOT NULL,kind TEXT NOT NULL,filter_json TEXT NOT NULL,generation INTEGER NOT NULL,payload_json TEXT NOT NULL,generated_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE INDEX IF NOT EXISTS idx_cache_lookup ON analytics_cache(scope,kind,generation);
CREATE TABLE IF NOT EXISTS dns_events(id INTEGER PRIMARY KEY,import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,datetime TEXT NOT NULL,event_date TEXT NOT NULL,event_hour INTEGER NOT NULL,client_ip TEXT,client_mac TEXT,device TEXT,group_name TEXT,domain TEXT NOT NULL,action TEXT NOT NULL,category TEXT,query_type TEXT,rcode TEXT,raw TEXT);
CREATE INDEX IF NOT EXISTS idx_dns_date_hour ON dns_events(event_date,event_hour); CREATE INDEX IF NOT EXISTS idx_dns_action_date ON dns_events(action,event_date); CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_events(domain); CREATE INDEX IF NOT EXISTS idx_dns_group ON dns_events(group_name); CREATE INDEX IF NOT EXISTS idx_dns_device ON dns_events(device); CREATE INDEX IF NOT EXISTS idx_dns_import ON dns_events(import_id);
CREATE TABLE IF NOT EXISTS firewall_events(id INTEGER PRIMARY KEY,import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,datetime TEXT NOT NULL,event_date TEXT NOT NULL,event_hour INTEGER NOT NULL,interface TEXT,rule_number TEXT,tracker TEXT,action TEXT NOT NULL,direction TEXT,protocol TEXT,src_ip TEXT NOT NULL,host_name TEXT,device_name TEXT,username TEXT,group_name TEXT,src_port TEXT,dst_ip TEXT NOT NULL,dst_port TEXT,service_name TEXT,service_category TEXT,raw TEXT);
CREATE INDEX IF NOT EXISTS idx_fw_date_hour ON firewall_events(event_date,event_hour); CREATE INDEX IF NOT EXISTS idx_fw_action_date ON firewall_events(action,event_date); CREATE INDEX IF NOT EXISTS idx_fw_service ON firewall_events(service_name); CREATE INDEX IF NOT EXISTS idx_fw_dst ON firewall_events(dst_ip,dst_port); CREATE INDEX IF NOT EXISTS idx_fw_import ON firewall_events(import_id);'''
def con():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); c.executescript(SCHEMA); return c
con().close()
def classify(n):
 import re
 if re.match(r'^access-\d{4}-\d{2}-\d{2}\.csv$',n,re.I): return 'dns'
 if re.match(r'^filter-events-\d{4}-\d{2}-\d{2}\.csv$',n,re.I): return 'firewall'
def detect_encoding(p):
 for e in ('utf-8-sig','cp1252'):
  try:
   with open(p,encoding=e) as f: f.read(65536)
   return e
  except UnicodeDecodeError: pass
 return 'utf-8'
def import_csv(path):
 p=Path(path); kind=classify(p.name)
 if not kind: raise ValueError('Nome de arquivo não reconhecido.')
 h=hashlib.sha256();
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
 digest=h.hexdigest(); c=con()
 if c.execute('SELECT 1 FROM imports WHERE sha256=?',(digest,)).fetchone(): c.close(); return {'status':'duplicate','file':p.name}
 previous=c.execute('SELECT id FROM imports WHERE kind=? AND file_name=?',(kind,p.name)).fetchall(); updated=bool(previous)
 for previous_row in previous: c.execute('DELETE FROM imports WHERE id=?',(previous_row['id'],))
 c.commit()
 import re; m=re.search(r'(\d{4}-\d{2}-\d{2})',p.name); fdate=m.group(1) if m else ''
 cur=c.execute('INSERT INTO imports(kind,file_name,file_date,file_size,sha256) VALUES(?,?,?,?,?)',(kind,p.name,fdate,p.stat().st_size,digest)); iid=cur.lastrowid; accepted=rejected=0; enc=detect_encoding(p)
 try:
  with open(p,'r',encoding=enc,newline='') as f:
   sample=f.read(4096); f.seek(0); delim=';' if sample.count(';')>=sample.count(',') else ','; r=csv.DictReader(f,delimiter=delim)
   batch=[]
   for row in r:
    try:
     dt=(row.get('datetime') or row.get('date_time') or row.get('timestamp') or '').strip(); hour=int(dt[11:13]); date=dt[:10]
     if kind=='dns':
      dom=(row.get('domain') or '').rstrip('.').lower(); act=(row.get('action') or '').upper();
      if not dt or not dom or not act: raise ValueError()
      batch.append((iid,dt,date,hour,row.get('client_ip',''),row.get('client_mac','').upper(),row.get('device','') or row.get('client_ip',''),row.get('group','') or 'Sem grupo',dom,act,row.get('category','') or 'Não classificado',row.get('query_type','').upper(),row.get('rcode','').upper(),row.get('raw','')))
      if len(batch)>=5000:
       c.executemany('INSERT INTO dns_events(import_id,datetime,event_date,event_hour,client_ip,client_mac,device,group_name,domain,action,category,query_type,rcode,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',batch); c.commit(); accepted+=len(batch); batch=[]
     else:
      act=(row.get('action') or '').upper(); src=row.get('src_ip',''); dst=row.get('dst_ip','');
      if not dt or not act or not src or not dst: raise ValueError()
      batch.append((iid,dt,date,hour,row.get('interface',''),row.get('rule_number',''),row.get('tracker',''),act,(row.get('direction') or '').upper(),(row.get('protocol') or '').upper(),src,row.get('host_name','') or src,row.get('device_name',''),row.get('username',''),row.get('group','') or 'Sem grupo',row.get('src_port',''),dst,row.get('dst_port',''),row.get('service_name',''),row.get('service_category','') or 'Não classificado',row.get('raw','')))
      if len(batch)>=5000:
       c.executemany('INSERT INTO firewall_events(import_id,datetime,event_date,event_hour,interface,rule_number,tracker,action,direction,protocol,src_ip,host_name,device_name,username,group_name,src_port,dst_ip,dst_port,service_name,service_category,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',batch); c.commit(); accepted+=len(batch); batch=[]
    except Exception: rejected+=1
   if batch:
    sql='INSERT INTO dns_events(import_id,datetime,event_date,event_hour,client_ip,client_mac,device,group_name,domain,action,category,query_type,rcode,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)' if kind=='dns' else 'INSERT INTO firewall_events(import_id,datetime,event_date,event_hour,interface,rule_number,tracker,action,direction,protocol,src_ip,host_name,device_name,username,group_name,src_port,dst_ip,dst_port,service_name,service_category,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    c.executemany(sql,batch); accepted+=len(batch)
   c.execute('UPDATE imports SET rows_accepted=?,rows_rejected=? WHERE id=?',(accepted,rejected,iid)); c.commit(); cache_clear(); prewarm_metrics(kind); return {'status':'updated' if updated else 'ok','file':p.name,'kind':kind,'accepted':accepted,'rejected':rejected,'metrics_cache':'ready'}
 except Exception: c.execute('DELETE FROM imports WHERE id=?',(iid,)); c.commit(); raise
 finally: c.close()
def where(kind,q,alias=''):
 p=[]; w=[]; pref=(alias+'.') if alias else ''
 def val(k): return (q.get(k) or [''])[0].strip()
 start=(val('from')+' '+(val('from_time') or '00:00')+':00') if val('from') else ''
 end=(val('to')+' '+(val('to_time') or '23:59')+':59') if val('to') else ''
 if start: w.append(pref+'datetime>=?'); p.append(start)
 if end: w.append(pref+'datetime<=?'); p.append(end)
 if val('action'): w.append(pref+'action=?'); p.append(val('action').upper())
 if val('group'): w.append(pref+'group_name LIKE ?'); p.append('%'+val('group')+'%')
 if kind=='dns':
  for k,col in [('device','device'),('ip','client_ip'),('mac','client_mac'),('domain','domain')]:
   if val(k): w.append(pref+col+' LIKE ?'); p.append('%'+val(k)+'%')
 else:
  if val('source'):
   w.append('('+pref+'host_name LIKE ? OR '+pref+'src_ip LIKE ? OR '+pref+'username LIKE ? OR '+pref+'src_port LIKE ?)'); p.extend(['%'+val('source')+'%']*4)
  if val('destination'):
   w.append('('+pref+'dst_ip LIKE ? OR '+pref+'dst_port LIKE ? OR '+pref+'service_name LIKE ?)'); p.extend(['%'+val('destination')+'%']*3)
  for k,col in [('service','service_name'),('category','service_category'),('port','dst_port')]:
   if val(k): w.append(pref+col+' LIKE ?'); p.append('%'+val(k)+'%')
 return (' WHERE '+' AND '.join(w) if w else ''),p

def dashboard(kind,q):
 cached=cache_get('dashboard',kind,q)
 if cached is not None:return cached
 c=con(); w,p=where(kind,q); table='dns_events' if kind=='dns' else 'firewall_events'
 total=c.execute(f'SELECT COUNT(*) n FROM {table}{w}',p).fetchone()['n']; hours=[0]*24
 for x in c.execute(f'SELECT event_hour h,COUNT(*) n FROM {table}{w} GROUP BY event_hour',p): hours[x['h']]=x['n']
 if kind=='dns':
  allowed=c.execute(f"SELECT COUNT(*) n FROM {table}{w + (' AND ' if w else ' WHERE ')}action='ALLOWED'",p).fetchone()['n']; blocked=c.execute(f"SELECT COUNT(*) n FROM {table}{w + (' AND ' if w else ' WHERE ')}action IN ('BLOCKED','BLOCK','REFUSED','NXDOMAIN')",p).fetchone()['n']; unique=c.execute(f'SELECT COUNT(DISTINCT domain) n FROM {table}{w}',p).fetchone()['n']; devices=c.execute(f"SELECT COUNT(DISTINCT COALESCE(NULLIF(device,''),client_ip)) n FROM {table}{w}",p).fetchone()['n']; tops={}
  for name,cond in [('allowed',"action='ALLOWED'"),('blocked',"action IN ('BLOCKED','BLOCK','REFUSED','NXDOMAIN')")]: tops[name]=[dict(x) for x in c.execute(f'SELECT domain name,COUNT(*) value FROM {table}{w + (" AND " if w else " WHERE ")}{cond} GROUP BY domain ORDER BY value DESC LIMIT 10',p)]
  tops['devices']=[dict(x) for x in c.execute(f'SELECT COALESCE(NULLIF(device,""),client_ip) name,COUNT(*) value FROM {table}{w} GROUP BY name ORDER BY value DESC LIMIT 10',p)]; data={'total':total,'allowed':allowed,'blocked':blocked,'rate':blocked*100/total if total else 0,'unique':unique,'devices':devices,'hours':hours,'tops':tops}
 else:
  pas=c.execute(f"SELECT COUNT(*) n FROM {table}{w + (' AND ' if w else ' WHERE ')}action='PASS'",p).fetchone()['n']; blocked=c.execute(f"SELECT COUNT(*) n FROM {table}{w + (' AND ' if w else ' WHERE ')}action IN ('BLOCK','BLOCKED','REJECT')",p).fetchone()['n']; data={'total':total,'allowed':pas,'blocked':blocked,'rate':blocked*100/total if total else 0,'hours':hours,'tops':{'services':[dict(x) for x in c.execute(f'SELECT service_name name,COUNT(*) value FROM {table}{w} GROUP BY service_name ORDER BY value DESC LIMIT 10',p)]}}
 c.close(); cache_set('dashboard',kind,q,data); return data

def status_payload():
 c=con()
 try:
  integrity=c.execute("PRAGMA quick_check").fetchone()[0]
  last=c.execute("SELECT * FROM imports ORDER BY imported_at DESC LIMIT 1").fetchone()
  dns=c.execute("SELECT COUNT(*) n FROM dns_events").fetchone()[0]
  fw=c.execute("SELECT COUNT(*) n FROM firewall_events").fetchone()[0]
  return {"status":"ok" if integrity=="ok" else "error","database":"OK" if integrity=="ok" else integrity,"database_path":str(DB),"cache_entries":c.execute("SELECT COUNT(*) FROM analytics_cache").fetchone()[0],"generation":current_generation(c),"dns":dns,"firewall":fw,"last":dict(last) if last else None}
 finally: c.close()

def select_files():
 try:
  import tkinter as tk
  from tkinter import filedialog
  root=tk.Tk(); root.withdraw(); root.attributes('-topmost',True)
  files=filedialog.askopenfilenames(title='Selecionar CSVs do Block Manager',filetypes=[('CSV Block Manager','*.csv'),('Todos os arquivos','*.*')])
  root.destroy(); return list(files)
 except Exception as e:
  raise RuntimeError(f'Selecao de arquivos indisponivel: {e}')

def report_payload(kind,q):
 cached=cache_get('report',kind,q)
 if cached is not None:return cached
 c=con(); w,p=where(kind,q); table='dns_events' if kind=='dns' else 'firewall_events'
 try:
  def rows(sql,args=None): return [dict(x) for x in c.execute(sql,p if args is None else args)]
  def rank(col, extra='', limit=10):
   tail=(w + (' AND ' if w else ' WHERE ') + extra) if extra else w
   sql="SELECT COALESCE(NULLIF("+col+",''),'Não classificado') name,COUNT(*) value FROM "+table+tail+" GROUP BY name ORDER BY value DESC LIMIT "+str(int(limit))
   return rows(sql)
  if kind=='dns':
   data={'categories':rank('category'),'groups':rank('group_name'),'query_types':rank('query_type'),'rcodes':rank('rcode'),'blocked_categories':rank('category',"action IN ('BLOCKED','BLOCK','REFUSED','NXDOMAIN')"),'recent':[]}; cache_set('report',kind,q,data); return data
  uqsvc="SELECT COUNT(DISTINCT service_name) n FROM firewall_events"+w+(" AND " if w else " WHERE ")+"service_name<>''"
  data={'destinations':rank('dst_ip'),'blocked_destinations':rank('dst_ip',"action IN ('BLOCK','BLOCKED','REJECT')"),'blocked_hosts':rank("COALESCE(NULLIF(host_name,''),src_ip)","action IN ('BLOCK','BLOCKED','REJECT')"),'blocked_services':rank('service_name',"action IN ('BLOCK','BLOCKED','REJECT')"),'blocked_categories':rank('service_category',"action IN ('BLOCK','BLOCKED','REJECT')"),'allowed_services':rank('service_name',"action='PASS'"),'ports':rank('dst_port'),'blocked_ports':rank('dst_port',"action IN ('BLOCK','BLOCKED','REJECT')"),'groups':rank('group_name'),'protocols':rank('protocol'),'interfaces':rank('interface'),'unique_hosts':c.execute('SELECT COUNT(DISTINCT src_ip) n FROM firewall_events'+w,p).fetchone()['n'],'unique_destinations':c.execute('SELECT COUNT(DISTINCT dst_ip) n FROM firewall_events'+w,p).fetchone()['n'],'unique_services':c.execute(uqsvc,p).fetchone()['n'],'recent':[]}; cache_set('report',kind,q,data); return data
 finally:c.close()

def prewarm_metrics(kind):
 q={}
 dashboard(kind,q)
 report_payload(kind,q)
 return True

def paged_events(kind,q):
 c=con(); w,p=where(kind,q)
 try:
  page=max(1,int((q.get('page') or ['1'])[0] or 1)); size=int((q.get('page_size') or ['100'])[0] or 100); size=size if size in (50,100,250,500) else 100
  table='dns_events' if kind=='dns' else 'firewall_events'
  cols=['datetime','action','client_ip','client_mac','device','group_name','domain','category','query_type','rcode'] if kind=='dns' else ['datetime','action','protocol','host_name','src_ip','src_port','group_name','dst_ip','dst_port','service_name','service_category','interface','rule_number','tracker']
  total=c.execute('SELECT COUNT(*) n FROM '+table+w,p).fetchone()['n']; pages=max(1,(total+size-1)//size); page=min(page,pages); offset=(page-1)*size
  data=[dict(x) for x in c.execute('SELECT '+','.join(cols)+' FROM '+table+w+' ORDER BY datetime DESC LIMIT ? OFFSET ?',p+[size,offset])]
  return {'kind':kind,'columns':cols,'rows':data,'total':total,'page':page,'page_size':size,'pages':pages}
 finally:c.close()

def print_html(kind,q):
 import html
 preview=paged_events(kind,{**q,'page':['1'],'page_size':['500']}); total=preview['total']; limited=total>10000
 if limited:
  cols=preview['columns']; rows=[tuple(r.get(c,'') for c in cols) for r in preview['rows']]
 else: cols,rows=export_rows(kind,q)
 title='Relatório DNS' if kind=='dns' else 'Relatório Firewall'
 labels={'datetime':'Data/Hora','action':'Ação','client_ip':'IP','client_mac':'MAC','device':'Dispositivo','group_name':'Grupo','domain':'Domínio','category':'Categoria','query_type':'Tipo','rcode':'Resposta','protocol':'Protocolo','host_name':'Host','src_ip':'IP origem','src_port':'Porta origem','dst_ip':'Destino','dst_port':'Porta','service_name':'Serviço','service_category':'Categoria','interface':'Interface','rule_number':'Regra','tracker':'Tracker'}
 filters=[]
 for key in ('from','from_time','to','to_time','action','group','device','ip','mac','domain','source','destination','service','category','port'):
  v=(q.get(key) or [''])[0]
  if v: filters.append(key+': '+v)
 warning=("<div class='warning'><b>Visualização gerencial:</b> o resultado contém %s registros. Para proteger o navegador, os detalhes exibem uma amostra de 500 entradas. Use Exportar CSV para obter todas as entradas.</div>"%total) if limited else ''
 head=''.join('<th>'+html.escape(labels.get(c,c))+'</th>' for c in cols)
 rows_html=''.join('<tr>'+''.join('<td>'+html.escape(str(v or ''))+'</td>' for v in row)+'</tr>' for row in rows)
 template="""<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'><title>{title}</title><style>@page{{size:landscape;margin:8mm}}body{{font:9px Arial;color:#222}}h1{{color:#087565;margin:0 0 4px}}.meta{{margin-bottom:10px;color:#555}}.warning{{padding:10px;margin:8px 0;background:#fff4d8;border-left:4px solid #d58d00;color:#795500}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #bbb;padding:3px;text-align:left;word-break:break-word}}th{{background:#e8f3f1;color:#045c4c}}.toolbar{{margin-bottom:10px}}button,a{{display:inline-block;padding:8px 12px;background:#087565;color:white;border:0;border-radius:5px;text-decoration:none;margin-right:6px;cursor:pointer}}button.secondary{{background:#52636c}}@media print{{.toolbar{{display:none}}thead{{display:table-header-group}}tr{{break-inside:avoid}}}}</style></head><body><div class='toolbar'><button onclick='window.print()'>Salvar como PDF</button><a id='downloadHtml' href='#'>Baixar HTML</a><button class='secondary' onclick='window.close()'>Fechar</button></div><h1>STW Block Manager Analytics - {title}</h1><div class='meta'>{count} registro(s) filtrado(s) · {filters}</div>{warning}<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table><script>const u=new URL(location.href);u.pathname='/api/html';document.getElementById('downloadHtml').href=u.toString();</script></body></html>"""
 return template.format(title=html.escape(title),count=total,warning=warning,filters=html.escape(' | '.join(filters) if filters else 'Sem filtros'),head=head,rows=rows_html)

def export_rows(kind,q):
 c=con(); w,p=where(kind,q)
 try:
  if kind=='dns':
   cols=['datetime','client_ip','client_mac','device','group_name','domain','action','category','query_type','rcode']; table='dns_events'
  else:
   cols=['datetime','action','protocol','host_name','src_ip','src_port','group_name','dst_ip','dst_port','service_name','service_category','interface','rule_number','tracker']; table='firewall_events'
  return cols,[tuple(x[c] or '' for c in cols) for x in c.execute('SELECT '+','.join(cols)+' FROM '+table+w+' ORDER BY datetime DESC',p)]
 finally:c.close()

class H(SimpleHTTPRequestHandler):
 def translate_path(self,path): return str(ROOT/(urlparse(path).path.lstrip('/') or 'index.html'))
 def json(self,o,status=200):
  b=json.dumps(o,ensure_ascii=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',len(b));self.end_headers();self.wfile.write(b)
 def do_GET(self):
  u=urlparse(self.path); q=parse_qs(u.query)
  if u.path=='/api/dashboard': return self.json(dashboard((q.get('kind') or ['dns'])[0],q))
  if u.path=='/api/events': return self.json(paged_events((q.get('kind') or ['dns'])[0],q))
  if u.path=='/api/print':
   body=print_html((q.get('kind') or ['dns'])[0],q).encode('utf-8'); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
  if u.path=='/api/export':
   kind=(q.get('kind') or ['dns'])[0]; cols,data=export_rows(kind,q); import io
   out=io.StringIO(); wr=csv.writer(out,delimiter=';',lineterminator='\r\n'); wr.writerow(cols); wr.writerows(data); body=('\ufeff'+out.getvalue()).encode('utf-8')
   self.send_response(200); self.send_header('Content-Type','text/csv; charset=utf-8'); self.send_header('Content-Disposition','attachment; filename=stw-'+kind+'-report.csv'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
  if u.path=='/api/html':
   kind=(q.get('kind') or ['dns'])[0]; body=print_html(kind,q).encode('utf-8'); stamp=(q.get('from') or ['completo'])[0] or 'completo'; name='STW-Relatorio-'+('DNS' if kind=='dns' else 'Firewall')+'-'+stamp+'.html'; self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Disposition','attachment; filename='+name); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
  if u.path=='/api/status': return self.json(status_payload())
  if u.path=='/api/report': return self.json(report_payload((q.get('kind') or ['dns'])[0],q))
  if u.path=='/api/select-files':
   try: return self.json({'files':select_files()})
   except Exception as e: return self.json({'error':str(e)},500)
  if u.path=='/api/imports':
   c=con(); r=[dict(x) for x in c.execute('SELECT * FROM imports ORDER BY imported_at DESC')];c.close();return self.json(r)
  return super().do_GET()
 def do_POST(self):
  if self.path!='/api/import': return self.json({'error':'not found'},404)
  n=int(self.headers.get('Content-Length','0')); obj=json.loads(self.rfile.read(n));
  try:return self.json(import_csv(obj['path']))
  except Exception as e:return self.json({'error':str(e)},400)
 def log_message(self,*a): pass
if __name__=='__main__':
 preferred=int(sys.argv[1]) if len(sys.argv)>1 else 8765
 for port in range(preferred, preferred+21):
  try:
   srv=ThreadingHTTPServer(('127.0.0.1',port),H); break
  except OSError:
   srv=None
 if srv is None: raise SystemExit('Nao foi possivel abrir uma porta local entre 8765 e 8785.')
 print(f'Block Manager Analytics V1.1.9 em http://127.0.0.1:{port}')
 for kind in ('dns','firewall'):
  try:
   if cache_get('dashboard',kind,{}) is None or cache_get('report',kind,{}) is None:
    print('Preparando cache de metricas '+kind+'...'); prewarm_metrics(kind)
  except Exception as exc: print('Aviso ao preparar cache '+kind+': '+str(exc))
 threading.Timer(.7,lambda:webbrowser.open(f'http://127.0.0.1:{port}')).start(); srv.serve_forever()
