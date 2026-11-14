require('dotenv').config();
const express=require('express'),{Pool}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path');
const SECRET=process.env.JWT_SECRET;
if(!SECRET){console.error('Thiếu JWT_SECRET trong file .env');process.exit(1)}
const pool=new Pool({host:process.env.PGHOST||'localhost',port:+(process.env.PGPORT||5432),user:process.env.PGUSER,password:process.env.PGPASSWORD,database:process.env.PGDATABASE,connectionTimeoutMillis:3000});
pool.on('error',e=>console.error('DB:',e.message));
const app=express();app.use(express.json());
const ORIGIN=process.env.ALLOW_ORIGIN;
if(ORIGIN)app.use((q,s,n)=>{s.set({'Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Headers':'Content-Type,Authorization,ngrok-skip-browser-warning','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'});if(q.method==='OPTIONS')return s.sendStatus(204);n()});
const wrap=f=>(q,s,n)=>f(q,s,n).catch(e=>{console.error(e.message);s.status(503).json({error:'Máy chủ gặp sự cố'})});
const D=/^\d{4}-\d{2}-\d{2}$/,int=v=>Math.max(0,Math.min(999,Math.floor(+v)||0));
const addDay=(d,n)=>{const t=new Date(d+'T00:00:00Z');t.setUTCDate(t.getUTCDate()+n);return t.toISOString().slice(0,10)};
const getState=async id=>(await pool.query('select streak,last_day as last,best,fusion,unl,pin,done_day,quest from streaks where user_id=$1',[id])).rows[0];
const token=id=>jwt.sign({id},SECRET,{expiresIn:'30d'});
const auth=wrap(async(q,s,n)=>{let p;try{p=jwt.verify((q.headers.authorization||'').slice(7),SECRET)}catch(e){return s.status(401).json({error:'Chưa đăng nhập'})}
  const u=(await pool.query('select id,username,is_admin from users where id=$1',[p.id])).rows[0];
  if(!u)return s.status(401).json({error:'Tài khoản không tồn tại'});q.uid=u.id;q.user=u;n()});

app.get('/api/health',async(q,s)=>{try{await pool.query('select 1');s.json({ok:true})}catch(e){s.status(503).json({ok:false})}});

app.post('/api/register',wrap(async(q,s)=>{
  const u=String(q.body.username||'').trim().toLowerCase(),p=String(q.body.password||'');
  if(!/^[a-z0-9_]{3,20}$/.test(u))return s.status(400).json({error:'Tên đăng nhập 3–20 ký tự: chữ, số, dấu _'});
  if(p.length<6)return s.status(400).json({error:'Mật khẩu tối thiểu 6 ký tự'});
  try{const r=await pool.query('with n as(insert into users(username,pass_hash) values($1,$2) returning id) insert into streaks(user_id) select id from n returning user_id',[u,await bcrypt.hash(p,10)]);
    s.json({token:token(r.rows[0].user_id)})}
  catch(e){if(e.code==='23505')return s.status(409).json({error:'Tên đăng nhập đã tồn tại'});throw e}}));

app.post('/api/login',wrap(async(q,s)=>{
  const r=(await pool.query('select id,pass_hash from users where username=$1',[String(q.body.username||'').trim().toLowerCase()])).rows[0];
  if(!r||!(await bcrypt.compare(String(q.body.password||''),r.pass_hash)))return s.status(401).json({error:'Sai tên đăng nhập hoặc mật khẩu'});
  s.json({token:token(r.id)})}));

app.get('/api/state',auth,wrap(async(q,s)=>s.json({user:{username:q.user.username,is_admin:q.user.is_admin},state:await getState(q.uid)})));

app.post('/api/light',auth,wrap(async(q,s)=>{
  const day=q.body.day;
  if(!D.test(day)||Math.abs(Date.parse(day+'T00:00:00Z')-Date.now())>2*864e5)return s.status(400).json({error:'Ngày không hợp lệ'});
  const r=await getState(q.uid);
  if(r.last===day&&!r.unl)return s.status(409).json({error:'Hôm nay bạn đã thắp rồi'});
  const n=((r.last===day||r.last===addDay(day,-1))?r.streak:0)+1;
  s.json((await pool.query('update streaks set streak=$2,last_day=$3,best=greatest(best,$2) where user_id=$1 returning streak,last_day as last,best,fusion,unl,pin,done_day,quest',[q.uid,n,day])).rows[0])}));

app.put('/api/state',auth,wrap(async(q,s)=>{
  const b=q.body||{};
  if(q.user.is_admin)await pool.query('update streaks set streak=$2,last_day=$3,best=$4,fusion=$5,unl=$6,pin=$7,done_day=$8,quest=$9 where user_id=$1',[q.uid,int(b.streak),D.test(b.last)?b.last:null,int(b.best),!!b.fusion,!!b.unl,b.pin==null?null:int(b.pin),D.test(b.done_day)?b.done_day:null,Math.max(0,Math.min(63,Math.floor(+b.quest)||0))]);
  else if(b.fusion===true)await pool.query('update streaks set fusion=true,done_day=coalesce(done_day,$2) where user_id=$1 and streak>=60',[q.uid,D.test(b.done_day)?b.done_day:null]);
  else return s.status(403).json({error:'Không có quyền admin'});
  s.json(await getState(q.uid))}));

app.post('/api/quest',auth,wrap(async(q,s)=>{
  const bit=+q.body.bit;if(![1,2,4,8,16,32].includes(bit))return s.status(400).json({error:'Bit không hợp lệ'});
  const r=await getState(q.uid);if(!r.fusion)return s.status(403).json({error:'Chưa tới giai đoạn này'});
  if(bit===32&&(r.quest&15)!==15)return s.status(403).json({error:'Chưa hoàn thành 4 thử thách'});
  await pool.query('update streaks set quest=quest|$2::int where user_id=$1',[q.uid,bit]);s.json(await getState(q.uid))}));

app.use(express.static(path.join(__dirname,'docs')));
app.listen(+(process.env.PORT||3000),()=>console.log('Chạy tại http://localhost:'+(process.env.PORT||3000)));
