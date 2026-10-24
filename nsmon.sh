#!/bin/bash
# nsmon — monitorizare multi-server netstreaming.eu
#  netstreaming.eu:  bash nsmon.sh panel
#  s2/s3/s4:         bash nsmon.sh agent <TOKEN> <IP_PANOU>
#  netstreaming.eu:  bash nsmon.sh add <nume> <IP> [port] | del <nume> | list | token
[ "$EUID" -eq 0 ] || { echo "Rulează ca root"; exit 1; }
APP=/opt/nsmon; SU=nsmonitor; APORT=8111; PPORT=8110; DOMAIN=netstreaming.eu
REPO_RAW=https://raw.githubusercontent.com/maxvideostar/monitor/main
mkdir -p $APP

deps(){
  echo ">> Pachete"; apt-get update -qq
  apt-get install -y -qq python3-flask python3-psutil openssl curl >/dev/null
  apt-get install -y -qq gunicorn >/dev/null 2>&1 || apt-get install -y -qq python3-gunicorn >/dev/null
  GUNI=$(command -v gunicorn || command -v gunicorn3)
  [ -n "$GUNI" ] || { echo "gunicorn nu s-a putut instala"; exit 1; }
  id $SU &>/dev/null || useradd -r -s /usr/sbin/nologin -d $APP $SU
  usermod -aG systemd-journal,adm $SU
  # curăță varianta veche (single-server)
  systemctl disable --now nsmonitor 2>/dev/null; rm -f /etc/systemd/system/nsmonitor.service /etc/sudoers.d/nsmonitor; rm -rf /opt/nsmonitor
}

detect(){
  SYSTEMCTL=$(command -v systemctl)
  NGINX=$(command -v nginx); if [ -z "$NGINX" ] && [ -x /usr/local/nginx/sbin/nginx ]; then NGINX=/usr/local/nginx/sbin/nginx; fi
  F2B=$(command -v fail2ban-client); NGDIR=""
  if [ -n "$NGINX" ]; then NGCONF=$($NGINX -V 2>&1 | grep -o 'conf-path=[^ ]*' | cut -d= -f2); NGDIR=$(dirname "${NGCONF:-/usr/local/nginx/conf/nginx.conf}"); fi
  UNITS=$($SYSTEMCTL list-units --type=service --all --no-legend --plain | awk '{print $1}' \
    | grep -Ei 'nginx|astra|ffmpeg|relay|stream|watchdog|fail2ban|gunicorn|monitor|srt|nts|udpxy|jellyfin' | grep -v nsmon | sort -u | tr '\n' ' ')
  HLS=""; DOM=""
  if [ -n "$NGDIR" ]; then
    HLS=$(grep -rhoP '^\s*hls_path\s+\K[^;]+' "$NGDIR" /etc/nginx 2>/dev/null | sort -u | tr '\n' ' ')
    DOM=$(grep -rhoP '^\s*server_name\s+\K[^ ;]+' "$NGDIR" /etc/nginx 2>/dev/null | grep '\.' | head -1)
  fi
  echo "   Servicii: $UNITS"; echo "   HLS: ${HLS:-—}"; echo "   nginx: ${NGINX:-—}"
}

install_agent(){ # $1 token  $2 IP-uri permise  $3 bind
  detect
  TOKEN="$1" ALLOW="$2" UNITS="$UNITS" HLS="$HLS" SYSTEMCTL="$SYSTEMCTL" NGINX="$NGINX" F2B="$F2B" DOM="${FORCEDOM:-$DOM}" python3 - <<'PY'
import os,json; e=os.environ
json.dump({"token":e["TOKEN"],"allow":e["ALLOW"].split(),"units":e["UNITS"].split(),"hls":e["HLS"].split(),
 "systemctl":e["SYSTEMCTL"],"nginx":e["NGINX"],"f2b":e["F2B"],"domain":e["DOM"]},open("/opt/nsmon/agent.json","w"),indent=1)
PY
  cat > $APP/agent.py <<'PYA'
import os,re,json,time,glob,subprocess,datetime,socket,hmac,psutil
from flask import Flask,request,jsonify,abort
C=json.load(open('/opt/nsmon/agent.json')); app=Flask(__name__)
@app.before_request
def chk():
    if C['allow'] and request.remote_addr not in C['allow']: abort(403)
    if not hmac.compare_digest(request.headers.get('X-Token',''),C['token']): abort(401)
def sh(c,t=10):
    try: return subprocess.run(c,capture_output=True,text=True,timeout=t).stdout
    except Exception as e: return str(e)
_n={'t':0}
def net():
    n=psutil.net_io_counters(); t=time.time(); r={'rx':0,'tx':0}
    if _n['t'] and t-_n['t']>0.5:
        dt=t-_n['t']; r={'rx':(n.bytes_recv-_n['rx'])*8/dt/1e6,'tx':(n.bytes_sent-_n['tx'])*8/dt/1e6}
    _n.update(t=t,rx=n.bytes_recv,tx=n.bytes_sent); return r
_s={'t':0,'d':None}
def ssl_days():
    if C['nginx'] and time.time()-_s['t']>3600:
        sn=f"-servername {C['domain']}" if C['domain'] else ''
        o=sh(['bash','-c',f"echo | openssl s_client -connect 127.0.0.1:443 {sn} 2>/dev/null | openssl x509 -noout -enddate"])
        m=re.search(r'notAfter=(.*)',o); d=None
        if m:
            try: d=(datetime.datetime.strptime(m.group(1).strip(),'%b %d %H:%M:%S %Y %Z')-datetime.datetime.utcnow()).days
            except Exception: pass
        _s.update(t=time.time(),d=d)
    return _s['d']
_f={'t':0,'v':'-'}
def f2b():
    if C['f2b'] and time.time()-_f['t']>60:
        j=re.findall(r'Jail list:\s*(.*)',sh(['sudo','-n',C['f2b'],'status'])); n=0
        for x in (j[0].split(',') if j else []):
            x=x.strip()
            if x:
                m=re.search(r'Currently banned:\s*(\d+)',sh(['sudo','-n',C['f2b'],'status',x])); n+=int(m.group(1)) if m else 0
        _f.update(t=time.time(),v=n if j else '-')
    return _f['v']
def hls():
    r=[]; now=time.time()
    for b in C['hls']:
        b=b.rstrip('/')
        for f in glob.glob(b+'/*.m3u8')+glob.glob(b+'/*/index.m3u8'):
            try: age=now-os.path.getmtime(f)
            except Exception: continue
            if age>86400: continue
            r.append({'name':os.path.basename(os.path.dirname(f)) if f.endswith('/index.m3u8') else os.path.basename(f)[:-5],'age':round(age,1)})
    return sorted(r,key=lambda x:x['name'])
def services():
    if not C['units']: return []
    o=sh(['systemctl','show','-p','Id,ActiveState,SubState']+C['units'])
    return [dict(l.split('=',1) for l in b.splitlines() if '=' in l) for b in o.strip().split('\n\n') if b.strip()]
_pc={}
def procs():
    out=[]; now=time.time()
    for p in psutil.process_iter(['pid','name','cmdline','create_time','memory_info']):
        n=p.info['name'] or ''
        if not re.search(r'ffmpeg|astra|srt|nts|udpxy',n,re.I): continue
        try:
            if p.pid not in _pc: _pc[p.pid]=p; p.cpu_percent(None); cpu=0
            else: cpu=_pc[p.pid].cpu_percent(None)
            out.append({'pid':p.pid,'name':n,'cpu':round(cpu,1),'mem':round(p.info['memory_info'].rss/1048576),
                        'up':now-p.info['create_time'],'cmd':' '.join(p.info['cmdline'] or [])[:200]})
        except Exception: pass
    for k in list(_pc):
        if not psutil.pid_exists(k): _pc.pop(k)
    return sorted(out,key=lambda x:-x['cpu'])
@app.get('/status')
def status():
    vm=psutil.virtual_memory(); disks=[]; seen=set()
    for p in psutil.disk_partitions():
        if p.mountpoint.startswith(('/snap','/boot')) or p.device in seen: continue
        seen.add(p.device)
        try: disks.append({'m':p.mountpoint,'p':psutil.disk_usage(p.mountpoint).percent})
        except Exception: pass
    return jsonify(host=socket.gethostname(),nginx=bool(C['nginx']),cpu=psutil.cpu_percent(interval=0.3),ram=vm.percent,disks=disks,
        load=[round(x,2) for x in os.getloadavg()],net=net(),uptime=time.time()-psutil.boot_time(),ssl=ssl_days(),f2b=f2b(),
        hls=hls(),svc=services(),procs=procs())
@app.get('/logs')
def logs():
    u=request.args.get('u','')
    if u not in C['units']: return jsonify(log='Unitate necunoscută')
    return jsonify(log=sh(['journalctl','-u',u,'-n','80','--no-pager','-o','short-iso']) or '(gol / fără acces)')
@app.post('/action')
def action():
    j=request.get_json(silent=True) or {}; a=j.get('a'); u=j.get('u')
    if a=='nginx-reload' and C['nginx']:
        t=subprocess.run(['sudo','-n',C['nginx'],'-t'],capture_output=True,text=True)
        if t.returncode: return jsonify(err='nginx -t a eșuat:\n'+t.stderr[-600:])
        cmd=['sudo','-n',C['nginx'],'-s','reload']
    elif a in ('restart','start') and u in C['units']: cmd=['sudo','-n',C['systemctl'],'--no-block',a,u]
    else: return jsonify(err='Acțiune invalidă')
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
    print(f"ACTION {a} {u} by {j.get('by','?')} rc={r.returncode}",flush=True)
    return jsonify(msg='OK — comandă trimisă') if r.returncode==0 else jsonify(err=r.stderr[-600:] or 'eroare')
PYA
  [ -f $APP/agent.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=nsmon-agent" \
     -keyout $APP/agent.key -out $APP/agent.crt 2>/dev/null
  {
    L=""; [ -n "$NGINX" ] && L="$NGINX -t, $NGINX -s reload"
    for u in $UNITS; do L="${L:+$L, }$SYSTEMCTL --no-block restart $u, $SYSTEMCTL --no-block start $u"; done
    [ -n "$F2B" ] && L="${L:+$L, }$F2B status, $F2B status *"
    [ -n "$L" ] && echo "$SU ALL=(root) NOPASSWD: $L"
  } > /etc/sudoers.d/nsmon
  chmod 440 /etc/sudoers.d/nsmon
  visudo -cf /etc/sudoers.d/nsmon >/dev/null || { echo "Eroare sudoers"; rm -f /etc/sudoers.d/nsmon; exit 1; }
  chown -R $SU:$SU $APP; chmod 600 $APP/*.json $APP/agent.key
  cat > /etc/systemd/system/nsmon-agent.service <<EOF
[Unit]
Description=nsmon agent
After=network.target
[Service]
User=$SU
WorkingDirectory=$APP
ExecStart=$GUNI -w 1 --threads 8 -b $3:$APORT --certfile $APP/agent.crt --keyfile $APP/agent.key agent:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload; systemctl enable nsmon-agent >/dev/null 2>&1; systemctl restart nsmon-agent
  if [ "$3" != "127.0.0.1" ] && command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    for ip in $2; do ufw allow from "$ip" to any port $APORT proto tcp >/dev/null; done; echo "   ufw: port $APORT deschis doar pentru $2"
  fi
}

install_panel(){
  F=$APP/panel.json
  if [ -f $F ]; then read -rp "Utilizator (gol = păstrează): " MUSER </dev/tty; else read -rp "Utilizator: " MUSER </dev/tty; fi
  [ -n "$MUSER" ] && { read -rsp "Parolă: " MPASS </dev/tty; echo; }
  [ ! -f $F ] && [ -z "$MPASS" ] && { echo "User/parolă obligatorii"; exit 1; }
  deps
  TOKEN=$(MUSER="$MUSER" MPASS="$MPASS" python3 - <<'PY'
import os,json,secrets
from werkzeug.security import generate_password_hash
e=os.environ; f='/opt/nsmon/panel.json'
c=json.load(open(f)) if os.path.exists(f) else {}
c.setdefault('secret',secrets.token_hex(32)); c.setdefault('token',secrets.token_hex(24))
c.setdefault('servers',{}); c['servers'].setdefault('main',{'url':'https://127.0.0.1:8111'})
if e.get('MUSER') and e.get('MPASS'): c['user']=e['MUSER']; c['hash']=generate_password_hash(e['MPASS'])
json.dump(c,open(f,'w'),indent=1); print(c['token'])
PY
)
  echo ">> Agent local"; FORCEDOM=$DOMAIN install_agent "$TOKEN" "127.0.0.1" 127.0.0.1
  echo ">> Panou"
  cat > $APP/panel.py <<'PYP'
import json,time,ssl,urllib.request,urllib.error,urllib.parse
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from flask import Flask,request,session,redirect,jsonify
from werkzeug.security import check_password_hash
CFG='/opt/nsmon/panel.json'
def cfg(): return json.load(open(CFG))
app=Flask(__name__); app.secret_key=cfg()['secret']
app.config.update(SESSION_COOKIE_NAME='nsmon',SESSION_COOKIE_PATH='/monitor',SESSION_COOKIE_HTTPONLY=True,
 SESSION_COOKIE_SECURE=True,SESSION_COOKIE_SAMESITE='Strict',PERMANENT_SESSION_LIFETIME=43200)
P='/monitor'; FAILS={}
CTX=ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
def ip(): return request.headers.get('CF-Connecting-IP') or request.headers.get('X-Real-IP') or request.remote_addr
def call(srv,path,data=None,t=8):
    C=cfg(); s=C['servers'].get(srv)
    if not s: return {'err':'Server necunoscut'}
    req=urllib.request.Request(s['url']+path,data=json.dumps(data).encode() if data is not None else None,
        headers={'X-Token':C['token'],'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=t,context=CTX) as r: return json.load(r)
    except urllib.error.HTTPError as e: return {'err':f'Agent HTTP {e.code}','offline':True}
    except Exception as e: return {'err':'OFFLINE: '+str(e)[:120],'offline':True}
def auth(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('ok'):
            return (jsonify(err='auth'),401) if request.path.startswith(P+'/api') else redirect(P+'/login')
        return f(*a,**k)
    return w
@app.after_request
def h(r):
    r.headers['Cache-Control']='no-store, private, max-age=0'; r.headers['CDN-Cache-Control']='no-store'
    r.headers['X-Frame-Options']='DENY'; return r
@app.route(P+'/login',methods=['GET','POST'])
def login():
    msg=''; C=cfg()
    if request.method=='POST':
        i=ip(); now=time.time(); FAILS[i]=[t for t in FAILS.get(i,[]) if now-t<600]
        if len(FAILS[i])>=5: msg='Prea multe încercări. Așteaptă 10 minute.'
        elif request.form.get('u')==C['user'] and check_password_hash(C['hash'],request.form.get('p','')):
            session.clear(); session['ok']=True; session.permanent=True; print(f"LOGIN OK {i}",flush=True); return redirect(P+'/')
        else: FAILS[i].append(now); msg='Utilizator sau parolă greșită'; print(f"LOGIN FAIL {i}",flush=True)
    return LOGIN.replace('%MSG%',msg)
@app.route(P+'/logout')
def logout(): session.clear(); return redirect(P+'/login')
@app.route(P)
def root(): return redirect(P+'/')
def page(s): return PAGE.replace('%SRV%',s).replace('%SERVERS%',json.dumps(list(cfg()['servers'])))
@app.route(P+'/')
@auth
def index(): return page('')
@app.route(P+'/<srv>')
@auth
def srvpage(srv): return page(srv) if srv in cfg()['servers'] else redirect(P+'/')
@app.get(P+'/api/overview')
@auth
def overview():
    names=list(cfg()['servers'])
    with ThreadPoolExecutor(8) as ex: res=list(ex.map(lambda n:call(n,'/status',t=6),names))
    out=[]
    for n,d in zip(names,res):
        if 'err' in d: out.append({'name':n,'online':False,'err':d['err']}); continue
        out.append({'name':n,'online':True,'host':d['host'],'cpu':d['cpu'],'ram':d['ram'],'load':d['load'][0],'uptime':d['uptime'],
          'ch':len(d['hls']),'ch_ok':sum(1 for c in d['hls'] if c['age']<15),'svc':len(d['svc']),
          'failed':sum(1 for s in d['svc'] if s.get('ActiveState')!='active'),'procs':len(d['procs']),'rx':d['net']['rx'],'tx':d['net']['tx']})
    return jsonify(out)
@app.get(P+'/api/<srv>/status')
@auth
def st(srv): return jsonify(call(srv,'/status'))
@app.get(P+'/api/<srv>/logs')
@auth
def lg(srv): return jsonify(call(srv,'/logs?u='+urllib.parse.quote(request.args.get('u',''))))
@app.post(P+'/api/<srv>/action')
@auth
def ac(srv):
    if request.headers.get('X-Req')!='1': return jsonify(err='csrf'),403
    j=request.get_json(silent=True) or {}
    print(f"ACTION {srv} {j.get('a')} {j.get('u')} by {ip()}",flush=True)
    return jsonify(call(srv,'/action',{'a':j.get('a'),'u':j.get('u'),'by':ip()},t=25))
CSS="""<meta name=viewport content="width=device-width,initial-scale=1"><style>
:root{--bg:#0b0f17;--c:#141b27;--b:#232d3f;--t:#e6edf7;--m:#8b98ad;--a:#3b82f6;--g:#22c55e;--y:#eab308;--r:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:14px system-ui,sans-serif}
.wrap{max-width:1150px;margin:auto;padding:16px}h1{font-size:18px;margin:0}h2{font-size:15px;margin:22px 0 8px;color:var(--m)}
header{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
nav{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0}nav a{padding:7px 14px;border-radius:8px;background:var(--c);border:1px solid var(--b);color:var(--t);text-decoration:none;text-transform:uppercase;font-size:13px}
nav a.on{background:var(--a);border-color:var(--a)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}.grid.big{grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
.card{background:var(--c);border:1px solid var(--b);border-radius:10px;padding:12px;color:var(--t);text-decoration:none;display:block}
.card b{display:block;color:var(--m);font-size:12px;font-weight:500;margin-bottom:4px}.card span{font-size:18px;font-weight:600}
.srv b{font-size:15px;color:var(--t);text-transform:uppercase}.srv div{margin-top:6px}.m{color:var(--m);font-size:12px}
.bar{height:5px;background:var(--b);border-radius:3px;margin-top:6px;overflow:hidden}.bar i{display:block;height:100%}
.g{background:var(--g)}.y{background:var(--y)}.r{background:var(--r)}
table{width:100%;border-collapse:collapse;background:var(--c);border:1px solid var(--b);border-radius:10px;overflow:hidden}
td{padding:9px 10px;border-top:1px solid var(--b);vertical-align:top}tr:first-child td{border-top:0}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px}.cmd{color:var(--m);font-size:11px;word-break:break-all}
button,a.btn{background:var(--a);color:#fff;border:0;border-radius:7px;padding:6px 11px;cursor:pointer;font-size:13px;text-decoration:none;margin:2px;display:inline-block}
button.sec,a.sec{background:var(--b)}.act{text-align:right;white-space:nowrap}
#modal{display:none;position:fixed;inset:0;background:#000a;align-items:center;justify-content:center;padding:12px}
#modal>div{background:var(--c);border:1px solid var(--b);border-radius:10px;width:100%;max-width:900px;max-height:85vh;display:flex;flex-direction:column}
#modal pre{margin:0;padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap}
input{width:100%;padding:10px;margin:6px 0 12px;background:var(--bg);border:1px solid var(--b);border-radius:7px;color:var(--t)}
</style>"""
LOGIN="<!doctype html><html><head><title>Monitor</title>"+CSS+"""</head><body><div class=wrap style="max-width:340px;margin-top:12vh">
<form method=post class=card><h1>netstreaming.eu monitor</h1><p style="color:var(--r)">%MSG%</p>
<label>Utilizator</label><input name=u autocomplete=username required><label>Parolă</label><input name=p type=password autocomplete=current-password required>
<button style="width:100%;padding:10px">Intră</button></form></div></body></html>"""
PAGE="<!doctype html><html><head><title>Monitor</title>"+CSS+"""</head><body><div class=wrap>
<header><h1>netstreaming.eu monitor <small id=ts style="color:var(--m);font-weight:400"></small></h1>
<div><button id=ngx style="display:none" onclick="act('nginx-reload')">Reload nginx</button><a class="btn sec" href="/monitor/logout">Ieșire</a></div></header>
<nav id=nav></nav>
<div id=all style="display:none"><div class="grid big" id=ov></div></div>
<div id=one style="display:none"><div id=err style="color:var(--r)"></div>
<h2>Sistem</h2><div class=grid id=cards></div>
<h2>Canale HLS (vechime playlist)</h2><table id=ch></table>
<h2>Procese (ffmpeg / astra / srt)</h2><table id=pr></table>
<h2>Servicii</h2><table id=sv></table></div></div>
<div id=modal onclick="if(event.target==this)this.style.display='none'"><div><header style="padding:10px 12px;border-bottom:1px solid var(--b)">
<b id=lt></b><button class=sec onclick="modal.style.display='none'">Închide</button></header><pre id=lp></pre></div></div>
<script>
const SRV='%SRV%',SERVERS=%SERVERS%,$=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
$('#nav').innerHTML=`<a href="/monitor/" class="${SRV?'':'on'}">Toate</a>`+SERVERS.map(s=>`<a href="/monitor/${s}" class="${s==SRV?'on':''}">${s}</a>`).join('');
async function api(u,o){const r=await fetch('/monitor/api/'+u,o);if(r.status==401){location='/monitor/login';throw 0}return r.json()}
function fmt(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return(d?d+'z ':'')+h+'h '+m+'m'}
function bar(p){return `<div class=bar><i class=${p>90?'r':p>75?'y':'g'} style="width:${p}%"></i></div>`}
const stamp=()=>$('#ts').textContent=new Date().toLocaleTimeString('ro-RO');
async function loadAll(){try{const d=await api('overview');
$('#ov').innerHTML=d.map(s=>s.online?`<a class="card srv" href="/monitor/${s.name}"><b><span class="dot ${s.failed||s.ch_ok<s.ch?'y':'g'}"></span>${s.name} <span class=m>${esc(s.host)}</span></b>
<div class=m>online · up ${fmt(s.uptime)} · load ${s.load}</div><div>CPU ${s.cpu.toFixed(0)}% ${bar(s.cpu)}</div><div>RAM ${s.ram.toFixed(0)}% ${bar(s.ram)}</div>
<div class=m>Canale ${s.ch_ok}/${s.ch} · Servicii ${s.svc-s.failed}/${s.svc} · Procese ${s.procs}</div><div class=m>↓${s.rx.toFixed(1)} ↑${s.tx.toFixed(1)} Mbps</div></a>`
:`<a class="card srv" href="/monitor/${s.name}"><b><span class="dot r"></span>${s.name}</b><div class=m>${esc(s.err)}</div></a>`).join('');stamp()}catch(e){}}
async function loadOne(){try{const d=await api(SRV+'/status');
if(d.err){$('#err').textContent=d.err;return}$('#err').textContent='';$('#ngx').style.display=d.nginx?'':'none';
$('#cards').innerHTML=[['Host',esc(d.host),''],['CPU',d.cpu.toFixed(0)+'%',bar(d.cpu)],['RAM',d.ram.toFixed(0)+'%',bar(d.ram)],...d.disks.map(x=>['Disc '+esc(x.m),x.p.toFixed(0)+'%',bar(x.p)]),
['Load',d.load.join(' / '),''],['Rețea','↓'+d.net.rx.toFixed(1)+' ↑'+d.net.tx.toFixed(1)+' Mbps',''],['Uptime',fmt(d.uptime),''],
...(d.nginx?[['SSL',d.ssl==null?'?':d.ssl+' zile','']]:[]),['Fail2ban',d.f2b+' banați','']].map(c=>`<div class=card><b>${c[0]}</b><span>${c[1]}</span>${c[2]}</div>`).join('');
$('#ch').innerHTML=d.hls.map(c=>`<tr><td><span class="dot ${c.age<15?'g':c.age<60?'y':'r'}"></span>${esc(c.name)}</td><td class=act>${c.age<120?c.age.toFixed(0)+'s':fmt(c.age)}</td></tr>`).join('')||'<tr><td class=m>Niciun playlist HLS pe acest server</td></tr>';
$('#pr').innerHTML=d.procs.map(p=>`<tr><td><b>${esc(p.name)}</b> <span class=m>pid ${p.pid} · up ${fmt(p.up)}</span><div class=cmd>${esc(p.cmd)}</div></td><td class=act>CPU ${p.cpu}%<br><span class=m>${p.mem} MB</span></td></tr>`).join('')||'<tr><td class=m>Niciun proces</td></tr>';
$('#sv').innerHTML=d.svc.map(s=>`<tr><td><span class="dot ${s.ActiveState=='active'?'g':s.ActiveState=='failed'?'r':'y'}"></span>${esc(s.Id)}</td><td>${esc(s.ActiveState)}/${esc(s.SubState)}</td><td class=act>
<button onclick="act('restart','${s.Id}')">Restart</button>${s.ActiveState!='active'?`<button onclick="act('start','${s.Id}')">Start</button>`:''}<button class=sec onclick="logs('${s.Id}')">Log</button></td></tr>`).join('')||'<tr><td class=m>Niciun serviciu detectat</td></tr>';
stamp()}catch(e){}}
async function act(a,u){if(!confirm(SRV.toUpperCase()+': '+(a=='nginx-reload'?'Reload nginx':a+' '+u)+'?'))return;
const r=await api(SRV+'/action',{method:'POST',headers:{'Content-Type':'application/json','X-Req':'1'},body:JSON.stringify({a,u})});alert(r.msg||r.err);setTimeout(loadOne,1500)}
async function logs(u){const r=await api(SRV+'/logs?u='+encodeURIComponent(u));$('#lt').textContent=SRV+' · '+u;$('#lp').textContent=r.log||r.err;$('#modal').style.display='flex';$('#lp').scrollTop=1e9}
if(SRV){$('#one').style.display='';loadOne();setInterval(loadOne,5000)}else{$('#all').style.display='';loadAll();setInterval(loadAll,5000)}
</script></body></html>"""
PYP
  chown -R $SU:$SU $APP; chmod 600 $APP/*.json
  cat > /etc/systemd/system/nsmon-panel.service <<EOF
[Unit]
Description=nsmon panel
After=network.target nsmon-agent.service
[Service]
User=$SU
WorkingDirectory=$APP
ExecStart=$GUNI -w 1 --threads 16 -b 127.0.0.1:$PPORT panel:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload; systemctl enable nsmon-panel >/dev/null 2>&1; systemctl restart nsmon-panel
  echo ">> nginx"
  [ -n "$NGINX" ] || { echo "   nginx negăsit — configurează manual proxy către 127.0.0.1:$PPORT"; return; }
  SNIP="$NGDIR/nsmonitor.conf"
  cat > "$SNIP" <<EOF
location ^~ /monitor {
    proxy_pass http://127.0.0.1:$PPORT;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 60s;
    proxy_buffering off;
    add_header Cache-Control "no-store, private" always;
}
EOF
  FILES=$(grep -rlE "server_name[^;]*[[:space:]]$DOMAIN[[:space:];]" "$NGDIR" /etc/nginx 2>/dev/null | sort -u)
  for f in $FILES; do cp -a "$f" "$f.bak-nsmon"; done
  python3 - "$SNIP" "$DOMAIN" $FILES <<'PY'
import re,sys
snip,dom,files=sys.argv[1],sys.argv[2],sys.argv[3:]
for f in files:
    s=open(f).read()
    if snip in s: print("   deja inclus în",f); continue
    ins=[]
    for m in re.finditer(r'\bserver\s*\{',s):
        d=1;i=m.end()
        while i<len(s) and d: d+=s[i]=='{'; d-=s[i]=='}'; i+=1
        b=s[m.end():i]; sn=re.search(r'server_name\s+([^;]*);',b)
        if not sn or dom not in sn.group(1).split() or not re.search(r'listen\s+[^;]*443',b): continue
        if re.search(r'location\s+(?:\^~\s*|=\s*)?/monitor/?\s*\{',b):
            print("   ATENȚIE: există deja location /monitor în",f,"— șterge-l și rulează din nou"); continue
        ins.append(m.end()+sn.end())
    for p in sorted(ins,reverse=True): s=s[:p]+f"\n    include {snip};"+s[p:]
    if ins: open(f,"w").write(s); print("   inclus în",f)
PY
  if $NGINX -t 2>/dev/null; then $NGINX -s reload; for f in $FILES; do rm -f "$f.bak-nsmon"; done
  else echo "   nginx -t a eșuat — revin"; $NGINX -t; for f in $FILES; do mv -f "$f.bak-nsmon" "$f"; done; $NGINX -s reload; fi
  PUBIP=$(curl -s4 --max-time 5 ifconfig.me)
  echo; echo "================ GATA ================"
  echo "Panou:  https://$DOMAIN/monitor"
  echo "Pe fiecare server rulează scriptul lui (ex. S2):"
  echo "  curl -fsSL $REPO_RAW/install-s2.sh | bash -s $TOKEN $PUBIP"
  echo "Apoi aici:  bash /root/nsmon.sh add s2 <IP_S2>   (la fel s3, s4)"
}

srv_edit(){ # add/del
  python3 - "$@" <<'PY'
import json,sys
f='/opt/nsmon/panel.json'; c=json.load(open(f)); a=sys.argv[1]; n=sys.argv[2].lower()
if a=='add': c['servers'][n]={'url':f"https://{sys.argv[3]}:{sys.argv[4]}"}; print("Adăugat",n,c['servers'][n]['url'])
else: c['servers'].pop(n,None); print("Șters",n)
json.dump(c,open(f,'w'),indent=1)
PY
}

need_panel(){ [ -f $APP/panel.json ] || { echo "Panoul nu e instalat aici. Rulează întâi: bash nsmon.sh panel"; exit 1; }; }

case "$1" in
  panel) install_panel ;;
  agent) [ -n "$2" ] && [ -n "$3" ] || { echo "Folosire: bash nsmon.sh agent <TOKEN> <IP_PANOU>"; exit 1; }
         deps; install_agent "$2" "$3" 0.0.0.0
         echo; echo "Agent pornit pe portul $APORT (HTTPS)."
         echo "Pe netstreaming.eu: bash /root/nsmon.sh add ${NSMON_NAME:-<nume>} $(curl -s4 --max-time 5 ifconfig.me)" ;;
  add)   need_panel; [ -n "$3" ] || { echo "Folosire: bash nsmon.sh add <nume> <IP> [port]"; exit 1; }
         srv_edit add "$2" "$3" "${4:-$APORT}"
         TOKEN=$(python3 -c "import json;print(json.load(open('$APP/panel.json'))['token'])")
         curl -sk --max-time 6 -H "X-Token: $TOKEN" "https://$3:${4:-$APORT}/status" | grep -q '"host"' \
           && echo "   Conexiune OK" || echo "   ATENȚIE: agentul nu răspunde (firewall / port $APORT / token)" ;;
  del)   need_panel; srv_edit del "$2" ;;
  list)  need_panel; python3 -c "import json;[print(k,v['url']) for k,v in json.load(open('$APP/panel.json'))['servers'].items()]" ;;
  token) need_panel; python3 -c "import json;print(json.load(open('$APP/panel.json'))['token'])" ;;
  *) echo "Folosire: bash nsmon.sh panel | agent <TOKEN> <IP_PANOU> | add <nume> <IP> [port] | del <nume> | list | token" ;;
esac
