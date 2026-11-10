import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
const ROOT=path.dirname(fileURLToPath(import.meta.url));
export class Fault extends Error {constructor(status,message){super(message);this.status=status}}
const fail=(s,m)=>{throw new Fault(s,m)}, rnd=()=>randomBytes(32).toString('base64url');
const TOOLS=['view','draw','zonage'];
export function makeApp(config){
 const {origin,supabaseUrl,publishableKey,secretKey,fetcher=fetch,development=false}=config;
 const site=new URL(origin),sb=new URL(supabaseUrl);
 if(site.origin!==origin||(!development&&site.protocol!=='https:'))throw Error('SITE_ORIGIN doit être une origine HTTPS sans chemin.');
 if(!development&&(sb.protocol!=='https:'||!sb.hostname.endsWith('.supabase.co')))throw Error('SUPABASE_URL invalide.');
 if(!publishableKey||!secretKey)throw Error('Clés serveur manquantes.');
 const cookieName=development?'egev_dev':'__Host-egev',sessions=new Map(),rates=new Map();
 const clean=setInterval(()=>{let now=Date.now();for(let[k,s]of sessions)if(now-s.created>8*3600e3||now-s.last>30*60e3)sessions.delete(k);for(let[k,r]of rates)if(now>r.until)rates.delete(k)},60000);clean.unref();
 const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
 const log=(event,user,detail='')=>console.log(JSON.stringify({time:new Date().toISOString(),event,user:user||null,detail}));
 function rate(key,limit,window=60000){let r=rates.get(key);if(!r||r.until<Date.now()){r={n:0,until:Date.now()+window};rates.set(key,r)}if(++r.n>limit)fail(429,'Trop de tentatives. Réessayez plus tard.');if(rates.size>20000)fail(503,'Service occupé.');}
 async function remote(route,{method='GET',body,token,admin=false}={}){
  const key=admin?secretKey:publishableKey,headers={apikey:key,'Content-Type':'application/json'};
  if(token)headers.Authorization='Bearer '+token;
  else if(admin&&key.split('.').length===3)headers.Authorization='Bearer '+key;
  let res;try{res=await fetcher(sb.origin+route,{method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(12000),redirect:'error'})}catch{fail(503,'Service d’authentification indisponible.')}
  const text=await res.text();let data;try{data=text?JSON.parse(text):null}catch{fail(502,'Réponse du service invalide.')}
  if(!res.ok){const e=new Fault(res.status===429?429:502,'Opération refusée par le service.');e.upstreamStatus=res.status;throw e}return data;
 }
 const cookie=(res,id)=>res.setHeader('Set-Cookie',`${cookieName}=${id}; Path=/; HttpOnly; SameSite=Strict${development?'':'; Secure'}; Max-Age=28800`);
 function session(req,res){let raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='))?.slice(cookieName.length+1),s=raw&&sessions.get(raw);if(s&&(Date.now()-s.created>8*3600e3||Date.now()-s.last>30*60e3)){sessions.delete(raw);s=null}if(!s){if(sessions.size>10000)fail(503,'Service occupé.');raw=rnd();s={id:raw,csrf:rnd(),created:Date.now(),last:Date.now()};sessions.set(raw,s);cookie(res,raw)}s.last=Date.now();return s}
 function rotate(s,res){sessions.delete(s.id);s.id=rnd();s.csrf=rnd();sessions.set(s.id,s);cookie(res,s.id)}
 function tokens(s,t){if(!t?.access_token||!t?.refresh_token)fail(502,'Session incomplète.');s.access=t.access_token;s.refresh=t.refresh_token;s.expires=Date.now()+(t.expires_in||3600)*1000;}
 async function auth(s){
  if(!s.access)fail(401,'Connexion requise.');
  if(s.expires<Date.now()+60000){if(!s.refreshing)s.refreshing=remote('/auth/v1/token?grant_type=refresh_token',{method:'POST',body:{refresh_token:s.refresh}}).then(t=>tokens(s,t)).finally(()=>s.refreshing=null);try{await s.refreshing}catch{delete s.access;fail(401,'Session expirée.')}}
  let user;try{user=await remote('/auth/v1/user',{token:s.access})}catch(e){if(e.upstreamStatus===401||e.upstreamStatus===403){delete s.access;fail(401,'Session expirée.')}throw e}
  if(!user?.id)fail(401,'Session invalide.');s.userId=user.id;
  const rows=await remote('/rest/v1/suite_profiles?id=eq.'+encodeURIComponent(user.id)+'&select=id,email,display_name,role,active,allowed_tools',{admin:true});
  const profile=rows?.[0];if(!profile?.active)fail(403,'Compte désactivé ou non autorisé.');
  // Token claims are read ONLY after /auth/v1/user has authenticated this exact token.
  let aal='aal1';try{aal=JSON.parse(Buffer.from(s.access.split('.')[1],'base64url')).aal||'aal1'}catch{}
  const verified=(user.factors||[]).filter(f=>f.factor_type==='totp'&&f.status==='verified');
  return{user,profile,aal,mfaRequired:profile.role==='admin'||verified.length>0,verified};
 }
 function full(a,s){if(s.passwordOnly)fail(403,'Définissez votre mot de passe avant de continuer.');if(a.mfaRequired&&a.aal!=='aal2')fail(403,'Double authentification requise.');}
 function admin(a,s){full(a,s);if(a.profile.role!=='admin')fail(403,'Administrateur requis.');}
 const publicProfile=a=>({...a.profile,mfa_required:a.mfaRequired&&a.aal!=='aal2'});
 async function body(req){if(!String(req.headers['content-type']||'').startsWith('application/json'))fail(415,'JSON requis.');let n=0,chunks=[];for await(const c of req){n+=c.length;if(n>16384)fail(413,'Requête trop volumineuse.');chunks.push(c)}try{return JSON.parse(Buffer.concat(chunks).toString())}catch{fail(400,'JSON invalide.')}}
 const email=v=>{if(typeof v!=='string'||v.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))fail(400,'Adresse e-mail invalide.');return v.trim().toLowerCase()};
 const password=v=>{if(typeof v!=='string'||v.length<14||v.length>128)fail(400,'Mot de passe : 14 à 128 caractères.');return v};
 function security(res,tool=false){res.setHeader('Cache-Control','no-store, max-age=0');res.setHeader('Pragma','no-cache');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(self)');if(!development)res.setHeader('Strict-Transport-Security','max-age=31536000');res.setHeader('Content-Security-Policy',tool?"default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://cdn.jsdelivr.net https://unpkg.com https://esm.sh https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self' https: blob:; worker-src 'self' blob:; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'":"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");}
 const json=(res,data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data))};
 const redirect=(res,to)=>{res.writeHead(303,{Location:to});res.end()};
 const publicFiles={'/login':'login.html','/activate':'activate.html','/mfa':'mfa.html','/assets/app.js':'app.js','/assets/style.css':'style.css','/assets/tool-session.js':'tool-session.js','/assets/icon-view.png':'assets/icon-view.png','/assets/icon-draw.png':'assets/icon-draw.png','/assets/icon-zonage.png':'assets/icon-zonage.png','/assets/icon-suite.svg':'assets/icon-suite.svg'};
 async function file(res,p){const data=await readFile(p);let ext=path.extname(p);res.writeHead(200,{'Content-Type':({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.svg':'image/svg+xml'})[ext]||'application/octet-stream'});res.end(data)}
 const server=http.createServer(async(req,res)=>{
  security(res);try{
   const url=new URL(req.url,origin),p=url.pathname;
   if(req.method==='GET'&&p==='/healthz')return json(res,{ok:true,version:'2.0'});
   if(req.method==='GET'&&publicFiles[p])return await file(res,path.join(ROOT,'public',publicFiles[p]));
   const s=session(req,res);
   if(p.startsWith('/api/')){
    if(req.method==='POST'){
     if(req.headers.origin!==origin)fail(403,'Origine refusée.');
     if(!equal(req.headers['x-csrf-token'],s.csrf))fail(403,'Protection CSRF : rechargez la page.');
     rate('global:'+req.socket.remoteAddress,120);
    }
    if(req.method==='GET'&&p==='/api/session')return json(res,{csrf:s.csrf,authenticated:!!s.access});
    if(req.method==='POST'&&p==='/api/login'){
     const b=await body(req),e=email(b.email);rate('login:'+createHash('sha256').update(e).digest('hex'),8,15*60e3);rate('login-ip:'+req.socket.remoteAddress,40,15*60e3);
     let t;try{t=await remote('/auth/v1/token?grant_type=password',{method:'POST',body:{email:e,password:password(b.password)}})}catch(x){if(x.status===503)throw x;fail(401,'Connexion refusée. Vérifiez vos informations.')}
     tokens(s,t);s.passwordOnly=false;try{const a=await auth(s);rotate(s,res);log('login',a.user.id);return json(res,{csrf:s.csrf,profile:publicProfile(a)})}catch(e){delete s.access;throw e}
    }
    if(req.method==='POST'&&p==='/api/recover'){
     const b=await body(req),e=email(b.email);rate('recover:'+createHash('sha256').update(e).digest('hex'),3,15*60e3);
     try{await remote('/auth/v1/recover?redirect_to='+encodeURIComponent(origin+'/activate'),{method:'POST',body:{email:e}})}catch{}
     return json(res,{message:'Si le compte existe, un message a été envoyé.'});
    }
    if(req.method==='POST'&&p==='/api/confirm'){
     const b=await body(req);if(!['invite','recovery'].includes(b.type)||typeof b.token_hash!=='string'||!/^[A-Za-z0-9_-]{20,256}$/.test(b.token_hash))fail(400,'Lien invalide.');rate('confirm:'+req.socket.remoteAddress,20,15*60e3);
     let t;try{t=await remote('/auth/v1/verify',{method:'POST',body:{token_hash:b.token_hash,type:b.type}})}catch{fail(400,'Lien expiré ou déjà utilisé.');}
     tokens(s,t);s.passwordOnly=true;const a=await auth(s);rotate(s,res);return json(res,{csrf:s.csrf,profile:publicProfile(a),password_required:true});
    }
    if(req.method==='POST'&&p==='/api/logout'){
     if(s.access)try{await remote('/auth/v1/logout?scope=local',{method:'POST',token:s.access})}catch{}
     sessions.delete(s.id);res.setHeader('Set-Cookie',`${cookieName}=; Path=/; HttpOnly; SameSite=Strict${development?'':'; Secure'}; Max-Age=0`);return json(res,{ok:true});
    }
    const a=await auth(s);
    if(req.method==='GET'&&p==='/api/me')return json(res,{profile:publicProfile(a),csrf:s.csrf,password_required:!!s.passwordOnly});
    if(req.method==='POST'&&p==='/api/password'){
     if(!s.passwordOnly)full(a,s);const b=await body(req);await remote('/auth/v1/user',{method:'PUT',token:s.access,body:{password:password(b.password)}});
     s.passwordOnly=false;for(const[id,other]of sessions)if(other!==s&&other.userId===a.user.id)sessions.delete(id);s.userId=a.user.id;rotate(s,res);log('password_changed',a.user.id);return json(res,{csrf:s.csrf,profile:publicProfile(a)});
    }
    if(p.startsWith('/api/mfa')){
     if(s.passwordOnly)fail(403,'Définissez d’abord le mot de passe.');rate('mfa:'+a.user.id,20,10*60e3);
     if(req.method==='GET'&&p==='/api/mfa')return json(res,{factors:a.verified.map(f=>({id:f.id,friendly_name:f.friendly_name})),required:a.mfaRequired&&a.aal!=='aal2'});
     if(req.method==='POST'&&p==='/api/mfa/enroll'){
      if(a.verified.length)fail(400,'Un facteur est déjà actif.');
      // Remove abandoned unverified TOTP factors before a new enrollment.
      for(const f of a.user.factors||[])if(f.factor_type==='totp'&&f.status==='unverified')await remote('/auth/v1/factors/'+encodeURIComponent(f.id),{method:'DELETE',token:s.access});
      const f=await remote('/auth/v1/factors',{method:'POST',token:s.access,body:{factor_type:'totp',friendly_name:'EGEV ONE',issuer:'EGEV ONE'}});s.pendingFactor=f.id;return json(res,{id:f.id,secret:f.totp?.secret});
     }
     if(req.method==='POST'&&p==='/api/mfa/verify'){
      const b=await body(req);if(!/^[0-9]{6}$/.test(b.code||'')||!((a.user.factors||[]).some(f=>f.id===b.factor_id)||s.pendingFactor===b.factor_id))fail(400,'Facteur ou code invalide.');
      const factor=encodeURIComponent(b.factor_id),ch=await remote('/auth/v1/factors/'+factor+'/challenge',{method:'POST',token:s.access,body:{}});
      const t=await remote('/auth/v1/factors/'+factor+'/verify',{method:'POST',token:s.access,body:{challenge_id:ch.id,code:b.code}});tokens(s,t);delete s.pendingFactor;const checked=await auth(s);if(checked.aal!=='aal2')fail(403,'Double authentification non validée.');rotate(s,res);return json(res,{csrf:s.csrf,profile:publicProfile(checked)});
     }
    }
    full(a,s);s.userId=a.user.id;
    if(req.method==='GET'&&p==='/api/admin/users'){admin(a,s);return json(res,{users:await remote('/rest/v1/suite_profiles?select=id,email,display_name,role,active,allowed_tools&order=created_at.desc&limit=1000',{admin:true})})}
    if(req.method==='POST'&&p==='/api/admin/invite'){
     admin(a,s);rate('invite:'+a.user.id,20,3600e3);const b=await body(req),e=email(b.email),name=typeof b.display_name==='string'?b.display_name.trim():'';
     if(!name||name.length>100||!Array.isArray(b.allowed_tools)||!b.allowed_tools.length||b.allowed_tools.some(x=>!TOOLS.includes(x)))fail(400,'Nom et modules requis.');
     // Role is NOT accepted from browser metadata. Every invite creates a regular user.
     const t=await remote('/auth/v1/invite?redirect_to='+encodeURIComponent(origin+'/activate'),{method:'POST',admin:true,body:{email:e,data:{display_name:name}}});const id=t.id||t.user?.id;if(!id)fail(502,'Invitation incomplète.');
     await remote('/rest/v1/suite_profiles?id=eq.'+encodeURIComponent(id),{method:'PATCH',admin:true,body:{display_name:name,allowed_tools:[...new Set(b.allowed_tools)],active:true,role:'user'}});log('invited',a.user.id,id);return json(res,{ok:true});
    }
    if(req.method==='POST'&&p==='/api/admin/update'){
     admin(a,s);const b=await body(req);if(typeof b.id!=='string'||!/^[a-f0-9-]{36}$/.test(b.id)||typeof b.active!=='boolean'||!Array.isArray(b.allowed_tools)||b.allowed_tools.some(x=>!TOOLS.includes(x)))fail(400,'Paramètres invalides.');
     const target=(await remote('/rest/v1/suite_profiles?id=eq.'+encodeURIComponent(b.id)+'&select=id,role',{admin:true}))?.[0];if(!target||target.role==='admin')fail(403,'Les comptes administrateurs sont gérés uniquement depuis Supabase.');
     await remote('/rest/v1/suite_profiles?id=eq.'+encodeURIComponent(b.id),{method:'PATCH',admin:true,body:{active:b.active,allowed_tools:[...new Set(b.allowed_tools)]}});
     for(const[id,other]of sessions)if(other.userId===b.id)sessions.delete(id);log('permissions_changed',a.user.id,b.id);return json(res,{ok:true});
    }
    fail(404,'Action inconnue.');
   }
   if(req.method!=='GET')fail(405,'Méthode interdite.');
   if(p==='/'||p==='/admin'||/^\/tools\/(view|draw|zonage)\.html$/.test(p)){
    let a;try{a=await auth(s);if(s.passwordOnly)return redirect(res,'/activate');if(a.mfaRequired&&a.aal!=='aal2')return redirect(res,'/mfa');full(a,s)}catch(e){if(e.status===401)return redirect(res,'/login');throw e}
    s.userId=a.user.id;
    if(p==='/')return await file(res,path.join(ROOT,'public/index.html'));
    if(p==='/admin'){admin(a,s);return await file(res,path.join(ROOT,'public/admin.html'))}
    const tool=p.split('/').pop().split('.')[0];if(a.profile.role!=='admin'&&!(a.profile.allowed_tools||[]).includes(tool))fail(403,'Module non autorisé.');security(res,true);return await file(res,path.join(ROOT,'private/tools',tool+'.html'));
   }
   fail(404,'Page introuvable.');
  }catch(e){if(res.headersSent){res.end();return}const status=e.status||500;if(status>=500)log('server_error',null,e.upstreamStatus?'upstream_'+e.upstreamStatus:'internal');json(res,{error:status===500?'Erreur interne.':e.message},status)}
 });
 server.requestTimeout=20000;server.headersTimeout=15000;server.maxHeadersCount=50;
 server.on('close',()=>clearInterval(clean));return server;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const development=process.env.NODE_ENV==='development';
 const server=makeApp({origin:process.env.SITE_ORIGIN,supabaseUrl:process.env.SUPABASE_URL,publishableKey:process.env.SUPABASE_PUBLISHABLE_KEY,secretKey:process.env.SUPABASE_SECRET_KEY,development});
 server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('EGEV ONE SUITE 2.0 démarré'));
}
