'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);
const statuses = ['Заплановано','У процесі','Виконано'];
const dbFile = process.env.DB_PATH || path.join(__dirname,'data','studyplan.sqlite');
if (dbFile !== ':memory:') fs.mkdirSync(path.dirname(dbFile),{recursive:true});
const db = new DatabaseSync(dbFile);
db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS subjects(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, normalized TEXT NOT NULL, UNIQUE(user_id,normalized), UNIQUE(id,user_id));
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, subject_id INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', date TEXT NOT NULL DEFAULT '', status TEXT NOT NULL CHECK(status IN ('Заплановано','У процесі','Виконано')), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(subject_id,user_id) REFERENCES subjects(id,user_id) ON DELETE RESTRICT);
CREATE INDEX IF NOT EXISTS task_owner ON tasks(user_id); CREATE INDEX IF NOT EXISTS subject_owner ON subjects(user_id);`);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const run = (sql,...args)=>db.prepare(sql).run(...args);
const get = (sql,...args)=>db.prepare(sql).get(...args);
const all = (sql,...args)=>db.prepare(sql).all(...args);
const fail=(status,message)=>{throw Object.assign(new Error(message),{status})};
const secure=process.env.NODE_ENV==='production' ? '; Secure' : '';
const cookie = (token,age) => `sp_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secure}`;
const readToken = req => (req.headers.cookie||'').match(/(?:^|;\s*)sp_session=([a-f0-9]{64})(?:;|$)/)?.[1];
function user(req){const token=readToken(req);return token&&get('SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=? AND expires>?',sha(token),Date.now());}
async function hashPassword(password){const salt=crypto.randomBytes(16).toString('hex');return salt+':'+(await scrypt(password,salt,64)).toString('hex');}
async function checkPassword(password,stored){const [salt,hash]=stored.split(':');return crypto.timingSafeEqual(Buffer.from(hash,'hex'),await scrypt(password,salt,64));}
function issue(req,res,id){const old=readToken(req);if(old)run('DELETE FROM sessions WHERE token_hash=?',sha(old));run('DELETE FROM sessions WHERE expires<=?',Date.now());const token=crypto.randomBytes(32).toString('hex');run('INSERT INTO sessions VALUES(?,?,?)',sha(token),id,Date.now()+7*86400000);res.setHeader('Set-Cookie',cookie(token,7*86400));}
function json(res,status,data){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(data));}
async function body(req){if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']||''))fail(415,'Потрібен формат JSON');let size=0;const chunks=[];for await(const c of req){size+=c.length;if(size>16384)fail(413,'Занадто великий запит');chunks.push(c);}try{const x=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!x||typeof x!=='object'||Array.isArray(x))throw Error();return x;}catch{fail(400,'Некоректний JSON');}}
function text(v,max,required=false){if(typeof v!=='string'||v.trim().length>max||(required&&!v.trim()))fail(400,'Перевірте заповнення полів');return v.trim();}
function validDate(v){if(v==='')return v;if(typeof v!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString().slice(0,10)!==v)fail(400,'Некоректна дата');return v;}
const attempts=new Map();
function limit(req){const now=Date.now();for(const [k,v] of attempts)if(v.until<now)attempts.delete(k);const k=req.socket.remoteAddress||'unknown',v=attempts.get(k)||{count:0,until:now+60000};if(++v.count>20)fail(429,'Забагато спроб. Спробуйте пізніше');attempts.set(k,v);}
const taskSelect='SELECT t.id,t.name,t.description,t.date,t.status,t.subject_id,t.created_at,s.name AS subject FROM tasks t JOIN subjects s ON t.subject_id=s.id';
async function handler(req,res){
res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
try{
const url=new URL(req.url,'http://localhost'), p=url.pathname,m=req.method;
if(!p.startsWith('/api/')){const files={'/':['index.html','text/html; charset=utf-8'],'/styles.css':['styles.css','text/css; charset=utf-8'],'/app.js':['app.js','text/javascript; charset=utf-8']};if(!files[p]||m!=='GET')return json(res,404,{error:'Сторінку не знайдено'});const [file,type]=files[p];res.setHeader('Content-Type',type);return res.end(fs.readFileSync(path.join(__dirname,'public',file)));}
if(m!=='GET'&&req.headers['sec-fetch-site']==='cross-site')fail(403,'Запит з іншого сайту');
if(p==='/api/health'&&m==='GET')return json(res,200,{ok:true});
if((p==='/api/register'||p==='/api/login')&&m==='POST'){
limit(req);const b=await body(req),email=text(b.email,254,true).toLowerCase(),password=b.password;
if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||typeof password!=='string'||password.length<8||password.length>128)fail(400,'Вкажіть email та пароль (8–128 символів)');
if(p==='/api/register'){const hash=await hashPassword(password);if(get('SELECT id FROM users WHERE email=?',email))fail(409,'Такий email вже зареєстровано');const id=Number(run('INSERT INTO users(email,password_hash) VALUES(?,?)',email,hash).lastInsertRowid);issue(req,res,id);return json(res,201,{id,email});}
const u=get('SELECT * FROM users WHERE email=?',email);if(!u){await scrypt(password,'dummy-salt',64);fail(401,'Неправильний email або пароль');}if(!await checkPassword(password,u.password_hash))fail(401,'Неправильний email або пароль');issue(req,res,u.id);return json(res,200,{id:u.id,email});}
if(p==='/api/logout'&&m==='POST'){const t=readToken(req);if(t)run('DELETE FROM sessions WHERE token_hash=?',sha(t));res.setHeader('Set-Cookie',cookie('',0));return json(res,200,{ok:true});}
const u=user(req);if(!u)fail(401,'Увійдіть до акаунта');const uid=u.id;
if(p==='/api/me'&&m==='GET')return json(res,200,u);
if(p==='/api/subjects'&&m==='GET')return json(res,200,all('SELECT id,name FROM subjects WHERE user_id=? ORDER BY id',uid));
if(p==='/api/tasks'&&m==='GET')return json(res,200,all(taskSelect+' WHERE t.user_id=? ORDER BY t.id DESC',uid));
const subjectMatch=p.match(/^\/api\/subjects\/(\d+)$/),taskMatch=p.match(/^\/api\/tasks\/(\d+)$/);
if((p==='/api/subjects'&&m==='POST')||(subjectMatch&&m==='PUT')){const b=await body(req),name=text(b.name,80,true),norm=name.toLocaleLowerCase('uk');const id=subjectMatch?Number(subjectMatch[1]):null;if(id&&!get('SELECT id FROM subjects WHERE id=? AND user_id=?',id,uid))fail(404,'Предмет не знайдено');if(get('SELECT id FROM subjects WHERE user_id=? AND normalized=? AND id<>?',uid,norm,id||0))fail(409,'Предмет вже існує');if(id){run('UPDATE subjects SET name=?,normalized=? WHERE id=? AND user_id=?',name,norm,id,uid);return json(res,200,{id,name});}const newId=Number(run('INSERT INTO subjects(user_id,name,normalized) VALUES(?,?,?)',uid,name,norm).lastInsertRowid);return json(res,201,{id:newId,name});}
if(subjectMatch&&m==='DELETE'){const id=Number(subjectMatch[1]);if(!get('SELECT id FROM subjects WHERE id=? AND user_id=?',id,uid))fail(404,'Предмет не знайдено');if(get('SELECT id FROM tasks WHERE subject_id=? AND user_id=?',id,uid))fail(409,'Спочатку видаліть або перенесіть завдання');run('DELETE FROM subjects WHERE id=? AND user_id=?',id,uid);return json(res,200,{ok:true});}
if(taskMatch&&m==='GET'){const t=get(taskSelect+' WHERE t.id=? AND t.user_id=?',Number(taskMatch[1]),uid);if(!t)fail(404,'Завдання не знайдено');return json(res,200,t);}
if((p==='/api/tasks'&&m==='POST')||(taskMatch&&m==='PUT')){const b=await body(req),id=taskMatch?Number(taskMatch[1]):null,old=id?get('SELECT * FROM tasks WHERE id=? AND user_id=?',id,uid):null;if(id&&!old)fail(404,'Завдання не знайдено');const v={...old,...b};const name=text(v.name,120,true),description=text(v.description??'',2000),date=validDate(v.date??''),status=v.status??statuses[0],sid=v.subject_id;if(!statuses.includes(status)||!Number.isSafeInteger(sid)||!get('SELECT id FROM subjects WHERE id=? AND user_id=?',sid,uid))fail(400,'Некоректний статус або предмет');if(id){run('UPDATE tasks SET name=?,description=?,date=?,status=?,subject_id=? WHERE id=? AND user_id=?',name,description,date,status,sid,id,uid);return json(res,200,get(taskSelect+' WHERE t.id=?',id));}const newId=Number(run('INSERT INTO tasks(user_id,subject_id,name,description,date,status) VALUES(?,?,?,?,?,?)',uid,sid,name,description,date,status).lastInsertRowid);return json(res,201,get(taskSelect+' WHERE t.id=?',newId));}
if(taskMatch&&m==='DELETE'){const r=run('DELETE FROM tasks WHERE id=? AND user_id=?',Number(taskMatch[1]),uid);if(!r.changes)fail(404,'Завдання не знайдено');return json(res,200,{ok:true});}
return json(res,404,{error:'Маршрут не знайдено'});
}catch(e){if(!e.status)console.error(e);if(!res.headersSent)json(res,e.status||500,{error:e.status?e.message:'Помилка сервера'});else res.end();}}
let server, mode;
try{const express=require('express');const app=express();app.disable('x-powered-by');app.use((req,res)=>handler(req,res));server=http.createServer(app);mode='Express';}catch(e){if(e.code!=='MODULE_NOT_FOUND'||!String(e.message).includes("'express'"))throw e;server=http.createServer(handler);mode='Node HTTP (offline fallback)';}
if(require.main===module)server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log(`StudyPlan: http://localhost:${server.address().port} | ${mode}`));
module.exports={server,db,mode};
