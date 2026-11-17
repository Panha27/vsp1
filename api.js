// Cloudflare Pages Function: accounts, single-device sessions, progress, question edits, backup.
// Needs a D1 database bound as DB and a secret ADMIN_PASSWORD (used only to create the first admin).
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json'}});
const enc=new TextEncoder();
async function hash(p,s){const k=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);const b=await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(s),iterations:100000,hash:'SHA-256'},k,256);return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
const hex=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(x=>x.toString(16).padStart(2,'0')).join('');
const SQL=['CREATE TABLE IF NOT EXISTS users(u TEXT PRIMARY KEY,s TEXT,h TEXT,role TEXT,name TEXT,dob TEXT,sex TEXT,f TEXT,t TEXT,off INTEGER DEFAULT 0,created TEXT)','CREATE TABLE IF NOT EXISTS sess(u TEXT PRIMARY KEY,tok TEXT,last INTEGER)','CREATE TABLE IF NOT EXISTS prog(u TEXT PRIMARY KEY,d TEXT,a TEXT,upd INTEGER)','CREATE TABLE IF NOT EXISTS edits(id INTEGER PRIMARY KEY,j TEXT,upd INTEGER,by TEXT)'];
let ready=false;const IDLE=30*60000,today=()=>new Date().toISOString().slice(0,10);
const pub=d=>({username:d.u,role:d.role,name:d.name,dob:d.dob,sex:d.sex,from:d.f,to:d.t});
const gate=d=>!d?'Wrong username or password.':d.off?'This account is disabled.':(d.role!=='admin'&&d.t&&d.t<today())?'Your access period ended on '+d.t+'. Please contact the administrator.':(d.role!=='admin'&&d.f&&d.f>today())?'Your access starts on '+d.f+'.':'';
export async function onRequest({request,env}){
 const DB=env.DB;if(!DB)return J({err:'Database not connected.'},500);
 if(!ready){for(const q of SQL)await DB.prepare(q).run();ready=true}
 const path=new URL(request.url).pathname.replace(/^\/api\/?/,'').replace(/\/$/,''),M=request.method;
 let b={};if(M!=='GET'){try{b=await request.json()}catch(e){}}
 const auth=request.headers.get('authorization');
 if(path==='ping'&&M==='GET'&&!auth)return J({ok:true});
 const one=(sql,...a)=>DB.prepare(sql).bind(...a).first(),run=(sql,...a)=>DB.prepare(sql).bind(...a).run();
 const progOf=async u=>{const p=await one('SELECT d,a FROM prog WHERE u=?',u);return{d:p&&p.d?JSON.parse(p.d):null,a:p&&p.a?JSON.parse(p.a):null}};
 if(path==='login'&&M==='POST'){const u=String(b.u||'').trim().toLowerCase();let d=await one('SELECT * FROM users WHERE u=?',u);
  if(!d&&u==='admin'&&env.ADMIN_PASSWORD&&b.p===env.ADMIN_PASSWORD&&!(await one('SELECT 1 x FROM users'))){const s=hex();await run('INSERT INTO users(u,s,h,role,created) VALUES(?,?,?,?,?)','admin',s,await hash(b.p,s),'admin',today());d=await one('SELECT * FROM users WHERE u=?',u)}
  if(!d||d.h!==await hash(String(b.p||''),d.s))return J({err:'Wrong username or password.'},401);
  const g=gate(d);if(g)return J({err:g},403);
  const tok=hex();await run('INSERT INTO sess(u,tok,last) VALUES(?,?,?) ON CONFLICT(u) DO UPDATE SET tok=excluded.tok,last=excluded.last',u,tok,Date.now()); // a new login replaces the old device's token
  return J({token:tok,user:pub(d),data:await progOf(u)})}
 const tok=(auth||'').replace(/^Bearer /,'');const S=tok&&await one('SELECT * FROM sess WHERE tok=?',tok);
 if(!S)return J({err:'You were logged out because this account was opened on another device, or the session ended.'},401);
 if(Date.now()-S.last>IDLE){await run('DELETE FROM sess WHERE u=?',S.u);return J({err:'Logged out after 30 minutes without activity. Please log in again.'},401)}
 await run('UPDATE sess SET last=? WHERE u=?',Date.now(),S.u);
 const me=await one('SELECT * FROM users WHERE u=?',S.u),g=gate(me);if(g)return J({err:g},401);const admin=me.role==='admin';
 if(path==='ping')return J({ok:true});
 if(path==='me')return J({user:pub(me),data:await progOf(S.u)});
 if(path==='logout'){await run('DELETE FROM sess WHERE u=?',S.u);return J({ok:true})}
 if(path==='progress'&&M==='PUT'){await run('INSERT INTO prog(u,d,a,upd) VALUES(?,?,?,?) ON CONFLICT(u) DO UPDATE SET d=excluded.d,a=excluded.a,upd=excluded.upd',S.u,JSON.stringify(b.d||null),JSON.stringify(b.a||null),Date.now());return J({ok:true})}
 if(path==='edits'&&M==='GET'){const r=await DB.prepare('SELECT id,j FROM edits').all(),o={};r.results.forEach(x=>o[x.id]=JSON.parse(x.j));return J(o)}
 if(!admin)return J({err:'Administrators only.'},403);
 if(path.startsWith('edits/')&&M==='PUT'){const id=parseInt(path.slice(6),10);if(!id)return J({err:'Bad id'},400);await run('INSERT INTO edits(id,j,upd,by) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET j=excluded.j,upd=excluded.upd,by=excluded.by',id,JSON.stringify(b),Date.now(),S.u);return J({ok:true})}
 if(path==='users'&&M==='GET'){const r=await DB.prepare('SELECT u,role,name,dob,sex,f,t,off FROM users ORDER BY u').all();return J({users:r.results})}
 if(path==='users'&&M==='POST'){const u=String(b.u||'').trim().toLowerCase();if(!u)return J({err:'Username required.'},400);const old=await one('SELECT * FROM users WHERE u=?',u);
  let s=old&&old.s,h=old&&old.h;if(b.p){s=hex();h=await hash(String(b.p),s)}if(!h)return J({err:'A password is required for a new account.'},400);
  const role=b.role==='admin'?'admin':'student';await run('INSERT INTO users(u,s,h,role,name,dob,sex,f,t,off,created) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(u) DO UPDATE SET s=excluded.s,h=excluded.h,role=excluded.role,name=excluded.name,dob=excluded.dob,sex=excluded.sex,f=excluded.f,t=excluded.t,off=excluded.off',u,s,h,role,b.name||'',b.dob||'',b.sex||'',b.f||'',b.t||'',b.off?1:0,today());
  if(b.p||b.off)await run('DELETE FROM sess WHERE u=?',u);return J({ok:true})}
 if(path==='users'&&M==='DELETE'){const u=String(b.u||'').toLowerCase();if(u===S.u)return J({err:'You cannot delete yourself.'},400);for(const t of['users','sess','prog'])await run('DELETE FROM '+t+' WHERE u=?',u);return J({ok:true})}
 if(path==='backup'){const q=async t=>(await DB.prepare('SELECT * FROM '+t).all()).results;return J({when:new Date().toISOString(),users:await q('users'),prog:await q('prog'),edits:await q('edits')})}
 if(path==='restore'&&M==='POST'){for(const x of b.users||[])await run('INSERT OR REPLACE INTO users(u,s,h,role,name,dob,sex,f,t,off,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)',x.u,x.s,x.h,x.role,x.name,x.dob,x.sex,x.f,x.t,x.off||0,x.created||today());
  for(const x of b.prog||[])await run('INSERT OR REPLACE INTO prog(u,d,a,upd) VALUES(?,?,?,?)',x.u,x.d,x.a,x.upd||Date.now());for(const x of b.edits||[])await run('INSERT OR REPLACE INTO edits(id,j,upd,by) VALUES(?,?,?,?)',x.id,x.j,x.upd||Date.now(),x.by||'');return J({ok:true})}
 return J({err:'Not found'},404)}
