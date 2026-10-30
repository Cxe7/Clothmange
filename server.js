// مخزن الملابس: خادم بدون مكتبات خارجية. التشغيل: node server.js
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const PORT=process.env.PORT||3000,DIR=process.env.DATA_DIR||path.join(__dirname,"data");
fs.mkdirSync(DIR,{recursive:true});
const rd=(f,d)=>{try{return JSON.parse(fs.readFileSync(path.join(DIR,f),"utf8"))}catch(e){return d}};
const wr=(f,o)=>{const p=path.join(DIR,f);fs.writeFileSync(p+".tmp",JSON.stringify(o));fs.renameSync(p+".tmp",p)};
let DATA=rd("data.json",{v:1,docs:{}}),USERS=rd("users.json",{});
const SES=new Map(),FAIL={};
const hash=(pw,salt=crypto.randomBytes(16).toString("hex"))=>salt+":"+crypto.scryptSync(pw,salt,64).toString("hex");
const ok=(pw,h)=>{const[s,x]=h.split(":"),y=hash(pw,s).split(":")[1];return crypto.timingSafeEqual(Buffer.from(x,"hex"),Buffer.from(y,"hex"))};
const out=(res,c,o,h={})=>{res.writeHead(c,{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...h});res.end(JSON.stringify(o))};
const err=(res,c,m)=>out(res,c,{error:m});
const read=req=>new Promise(r=>{let b="";req.on("data",c=>{b+=c;if(b.length>3e7)req.destroy()});req.on("end",()=>{try{r(JSON.parse(b||"{}"))}catch(e){r({})}})});
const pub=u=>({username:u,name:USERS[u].name,role:USERS[u].role});
const admins=()=>Object.values(USERS).filter(x=>x.role==="admin").length;
const signin=(res,u)=>{const t=crypto.randomBytes(24).toString("hex");SES.set(t,u);out(res,200,{user:pub(u)},{"set-cookie":`sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`})};
const norm=s=>String(s||"").trim().toLowerCase();
http.createServer(async(req,res)=>{try{
const url=new URL(req.url,"http://x"),p=url.pathname,m=req.method,ip=req.socket.remoteAddress;
if(!p.startsWith("/api/")){if(p!=="/")return err(res,404,"404");return fs.readFile(path.join(__dirname,"public","index.html"),(e,d)=>{res.writeHead(200,{"content-type":"text/html; charset=utf-8"});res.end(d)})}
const sid=(/(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie||"")||[])[1],me=SES.get(sid)&&USERS[SES.get(sid)]?SES.get(sid):null;
if(p==="/api/me")return out(res,200,Object.keys(USERS).length?(me?{user:pub(me)}:{anon:true}):{setup:true});
if(m==="POST"&&(p==="/api/login"||p==="/api/setup")){const b=await read(req),u=norm(b.username);
 if(p==="/api/setup"){if(Object.keys(USERS).length)return err(res,403,"تم الإعداد مسبقًا");if(!u||String(b.password||"").length<6)return err(res,400,"كلمة المرور 6 أحرف على الأقل");USERS[u]={name:b.name||u,role:"admin",hash:hash(b.password)};wr("users.json",USERS);return signin(res,u)}
 const f=FAIL[ip]||(FAIL[ip]={n:0,t:Date.now()});if(Date.now()-f.t>6e5){f.n=0;f.t=Date.now()}if(f.n>=8)return err(res,429,"محاولات كثيرة، انتظر 10 دقائق");
 if(!USERS[u]||!ok(String(b.password||""),USERS[u].hash)){f.n++;return err(res,401,"اسم المستخدم أو كلمة المرور خطأ")}f.n=0;return signin(res,u)}
if(m==="POST"&&p==="/api/logout"){SES.delete(sid);return out(res,200,{})}
if(!me)return err(res,401,"سجّل الدخول");
if(p==="/api/sync"){const v=+url.searchParams.get("v");return out(res,200,v===DATA.v?{v:DATA.v}:{v:DATA.v,docs:DATA.docs})}
if(USERS[me].role!=="admin")return err(res,403,"للمسؤولين فقط");
if(m==="POST"&&p==="/api/batch"){const b=await read(req);Object.assign(DATA.docs,b.set||{});(b.del||[]).forEach(k=>delete DATA.docs[k]);DATA.v++;wr("data.json",DATA);return out(res,200,{v:DATA.v})}
if(p==="/api/users"&&m==="GET")return out(res,200,Object.keys(USERS).map(pub));
if(p==="/api/users"&&m==="POST"){const b=await read(req),u=norm(b.username);if(!u||USERS[u]||String(b.password||"").length<6)return err(res,400,"اسم مستخدم مكرر أو فارغ، أو كلمة مرور قصيرة");USERS[u]={name:b.name||u,role:b.role==="admin"?"admin":"worker",hash:hash(b.password)};wr("users.json",USERS);return out(res,200,{})}
const mu=/^\/api\/users\/(.+)$/.exec(p),t=mu&&norm(decodeURIComponent(mu[1]));
if(t&&USERS[t]){
 if(m==="PUT"){const b=await read(req);
  if(b.role){if(b.role!=="admin"&&USERS[t].role==="admin"&&admins()<2)return err(res,400,"لا يمكن إزالة آخر مسؤول");USERS[t].role=b.role==="admin"?"admin":"worker"}
  if(b.password){if(String(b.password).length<6)return err(res,400,"كلمة المرور قصيرة");USERS[t].hash=hash(b.password);for(const[k,v]of SES)if(v===t&&k!==sid)SES.delete(k)}
  wr("users.json",USERS);return out(res,200,{})}
 if(m==="DELETE"){if(t===me)return err(res,400,"لا يمكنك حذف حسابك");delete USERS[t];wr("users.json",USERS);for(const[k,v]of SES)if(v===t)SES.delete(k);return out(res,200,{})}}
err(res,404,"غير موجود")}catch(e){err(res,500,"خطأ في الخادم")}}).listen(PORT,"0.0.0.0",()=>console.log("جاهز: http://localhost:"+PORT));
