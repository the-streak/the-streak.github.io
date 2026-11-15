require('dotenv').config();
const express=require('express'),{Pool}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),crypto=require('crypto');
const SECRET=process.env.JWT_SECRET||'';
if(SECRET.length<32||/doi-thanh/.test(SECRET)){console.error('JWT_SECRET phải dài ít nhất 32 ký tự và khác giá trị mẫu (xem file .env)');process.exit(1)}
const pool=new Pool({host:process.env.PGHOST||'localhost',port:+(process.env.PGPORT||5432),user:process.env.PGUSER,password:process.env.PGPASSWORD,database:process.env.PGDATABASE,connectionTimeoutMillis:3000});
pool.on('error',e=>console.error('DB:',e.message));
const app=express();app.set('trust proxy',1);app.disable('x-powered-by');
app.use(express.json({limit:'10kb'}));
app.use((q,s,n)=>{s.set({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'});n()});
const ORIGIN=process.env.ALLOW_ORIGIN;
if(ORIGIN)app.use((q,s,n)=>{s.set({'Access-Control-Allow-Origin':ORIGIN,'Vary':'Origin','Access-Control-Allow-Headers':'Content-Type,Authorization,ngrok-skip-browser-warning','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'});if(q.method==='OPTIONS')return s.sendStatus(204);n()});
const wrap=f=>(q,s,n)=>f(q,s,n).catch(e=>{console.error(e.message);s.status(503).json({error:'Máy chủ gặp sự cố'})});
// giới hạn số lần thử (chống dò mật khẩu)
const hits=new Map();
const lim=(max,ms)=>(q,s,n)=>{const k=q.ip+q.path,now=Date.now(),a=(hits.get(k)||[]).filter(t=>now-t<ms);
  if(a.length>=max)return s.status(429).json({error:'Thử quá nhiều lần, vui lòng đợi một lát'});a.push(now);hits.set(k,a);n()};
setInterval(()=>{const now=Date.now();for(const[k,a]of hits)if(!a.some(t=>now-t<3600000))hits.delete(k)},600000).unref();
const D=/^\d{4}-\d{2}-\d{2}$/,int=v=>Math.max(0,Math.min(999,Math.floor(+v)||0));
const iso=ms=>new Date(ms).toISOString().slice(0,10);
const okDay=d=>D.test(d)&&d>=iso(Date.now()-12*36e5)&&d<=iso(Date.now()+14*36e5);
const addDay=(d,n)=>{const t=new Date(d+'T00:00:00Z');t.setUTCDate(t.getUTCDate()+n);return iso(t)};
const getState=async id=>(await pool.query('select streak,last_day as last,best,fusion,unl,pin,done_day,quest from streaks where user_id=$1',[id])).rows[0];
const token=id=>jwt.sign({id},SECRET,{algorithm:'HS256',expiresIn:'30d'});
const sha=x=>crypto.createHash('sha256').update(String(x)).digest();
const DUMMY=bcrypt.hashSync('khong-ton-tai',10);
const auth=wrap(async(q,s,n)=>{let p;try{p=jwt.verify((q.headers.authorization||'').slice(7),SECRET,{algorithms:['HS256']})}catch(e){return s.status(401).json({error:'Chưa đăng nhập'})}
  const u=p.id&&(await pool.query('select id,username,is_admin from users where id=$1',[p.id])).rows[0];
  if(!u)return s.status(401).json({error:'Tài khoản không tồn tại'});q.uid=u.id;q.user=u;n()});

app.get('/api/health',async(q,s)=>{try{await pool.query('select 1');s.json({ok:true})}catch(e){s.status(503).json({ok:false})}});

app.post('/api/register',lim(5,3600000),wrap(async(q,s)=>{
  const u=String(q.body.username||'').trim().toLowerCase(),p=String(q.body.password||'');
  if(!/^[a-z0-9_]{3,20}$/.test(u))return s.status(400).json({error:'Tên đăng nhập 3–20 ký tự: chữ, số, dấu _'});
  if(p.length<6||p.length>72)return s.status(400).json({error:'Mật khẩu từ 6 đến 72 ký tự'});
  try{const r=await pool.query('with n as(insert into users(username,pass_hash) values($1,$2) returning id) insert into streaks(user_id) select id from n returning user_id',[u,await bcrypt.hash(p,10)]);
    s.json({token:token(r.rows[0].user_id)})}
  catch(e){if(e.code==='23505')return s.status(409).json({error:'Tên đăng nhập đã tồn tại'});throw e}}));

app.post('/api/login',lim(10,600000),wrap(async(q,s)=>{
  const r=(await pool.query('select id,pass_hash from users where username=$1',[String(q.body.username||'').trim().toLowerCase()])).rows[0];
  const ok=await bcrypt.compare(String(q.body.password||'').slice(0,72),r?r.pass_hash:DUMMY);
  if(!r||!ok)return s.status(401).json({error:'Sai tên đăng nhập hoặc mật khẩu'});
  s.json({token:token(r.id)})}));

app.get('/api/state',auth,wrap(async(q,s)=>s.json({user:{username:q.user.username,is_admin:q.user.is_admin},state:await getState(q.uid)})));

app.post('/api/light',auth,wrap(async(q,s)=>{
  const day=q.body.day;
  if(!okDay(day))return s.status(400).json({error:'Ngày không hợp lệ'});
  const r=await getState(q.uid);
  if(r.last&&day<r.last)return s.status(409).json({error:'Hôm nay bạn đã thắp rồi'});
  if(r.last===day&&!r.unl)return s.status(409).json({error:'Hôm nay bạn đã thắp rồi'});
  const n=((r.last===day||r.last===addDay(day,-1))?r.streak:0)+1;
  s.json((await pool.query('update streaks set streak=$2,last_day=$3,best=greatest(best,$2) where user_id=$1 returning streak,last_day as last,best,fusion,unl,pin,done_day,quest',[q.uid,n,day])).rows[0])}));

app.put('/api/state',auth,wrap(async(q,s)=>{
  const b=q.body||{};
  if(q.user.is_admin)await pool.query('update streaks set streak=$2,last_day=$3,best=$4,fusion=$5,unl=$6,pin=$7,done_day=$8,quest=$9 where user_id=$1',[q.uid,int(b.streak),D.test(b.last)?b.last:null,int(b.best),!!b.fusion,!!b.unl,b.pin==null?null:int(b.pin),D.test(b.done_day)?b.done_day:null,Math.max(0,Math.min(63,Math.floor(+b.quest)||0))]);
  else if(b.fusion===true)await pool.query('update streaks set fusion=true,done_day=coalesce(done_day,$2) where user_id=$1 and streak>=60',[q.uid,okDay(b.done_day)?b.done_day:null]);
  else return s.status(403).json({error:'Không có quyền admin'});
  s.json(await getState(q.uid))}));

// cổng admin: mật khẩu nằm trong .env của server, không nằm trong mã nguồn công khai
app.post('/api/admin/verify',lim(5,600000),auth,wrap(async(q,s)=>{
  const pw=process.env.ADMIN_PASSWORD;
  if(!q.user.is_admin||!pw)return s.status(403).json({error:'Tài khoản này không có quyền admin'});
  if(!crypto.timingSafeEqual(sha(q.body.password||''),sha(pw)))return s.status(401).json({error:'Sai mật khẩu'});
  s.json({ok:true})}));

// thử thách: server cấp vé lúc bắt đầu và kiểm tra thời gian chơi khi nộp kết quả
const MIN=[12,110,5,120],MAX=[330,150,330,330];
app.post('/api/quest/start',auth,wrap(async(q,s)=>{
  const i=+q.body.i;if(!(i>=0&&i<4))return s.status(400).json({error:'Thử thách không hợp lệ'});
  if(!(await getState(q.uid)).fusion)return s.status(403).json({error:'Chưa tới giai đoạn này'});
  s.json({ticket:jwt.sign({uid:q.uid,i,k:'qt',t:Date.now()},SECRET,{algorithm:'HS256',expiresIn:'20m'})})}));
app.post('/api/quest',auth,wrap(async(q,s)=>{
  const bit=+q.body.bit;if(![1,2,4,8,16,32].includes(bit))return s.status(400).json({error:'Bit không hợp lệ'});
  const r=await getState(q.uid);if(!r.fusion)return s.status(403).json({error:'Chưa tới giai đoạn này'});
  if(bit===32&&(r.quest&15)!==15)return s.status(403).json({error:'Chưa hoàn thành 4 thử thách'});
  if(bit<=8){const i=Math.log2(bit);let p;
    try{p=jwt.verify(String(q.body.ticket||''),SECRET,{algorithms:['HS256']})}catch(e){return s.status(400).json({error:'Phiên thử thách không hợp lệ, hãy chơi lại'})}
    const sec=(Date.now()-p.t)/1000;
    if(p.k!=='qt'||p.uid!==q.uid||p.i!==i||sec<MIN[i]||sec>MAX[i])return s.status(400).json({error:'Kết quả không hợp lệ (thời gian chơi bất thường)'})}
  await pool.query('update streaks set quest=quest|$2::int where user_id=$1',[q.uid,bit]);s.json(await getState(q.uid))}));

app.use(express.static(path.join(__dirname,'docs')));
app.use((e,q,s,n)=>s.status(400).json({error:'Yêu cầu không hợp lệ'}));
app.listen(+(process.env.PORT||3000),()=>console.log('Chạy tại http://localhost:'+(process.env.PORT||3000)));
