'use strict';
// Persistent local SQLite storage. Node.js >=22.13, no npm packages required.
const {DatabaseSync}=require('node:sqlite');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const DATA_DIR=path.join(__dirname,'data');fs.mkdirSync(DATA_DIR,{recursive:true,mode:0o700});
const db=new DatabaseSync(path.join(DATA_DIR,'goodpath.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,task_id TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('done','pending')),note TEXT NOT NULL DEFAULT '',completed_at TEXT NOT NULL DEFAULT '',updated_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,task_id));`);
function hash(x){return crypto.createHash('sha256').update(x).digest('hex')}
function validName(x){return typeof x==='string'&&/^[a-zA-Z0-9_]{3,32}$/.test(x)}
function validPass(x){return typeof x==='string'&&x.length>=8&&x.length<=128}
function register(username,password){if(!validName(username)||!validPass(password))throw Error('帳號須為 3–32 位英文數字或底線；密碼至少 8 位');const salt=crypto.randomBytes(16).toString('hex');const pwd=crypto.scryptSync(password,salt,64).toString('hex');try{db.prepare('INSERT INTO users(username,password_hash) VALUES (?,?)').run(username,salt+':'+pwd)}catch{throw Error('帳號已存在')}}
function login(username,password){const user=db.prepare('SELECT * FROM users WHERE username=?').get(username);if(!user||typeof password!=='string')throw Error('帳號或密碼不正確');const [salt,expected]=user.password_hash.split(':');const got=crypto.scryptSync(password,salt,64);if(!crypto.timingSafeEqual(got,Buffer.from(expected,'hex')))throw Error('帳號或密碼不正確');const token=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),user.id,Date.now()+7*86400000);return {token,username:user.username}}
function session(req){const m=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization||'');if(!m)return null;const row=db.prepare('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(hash(m[1]),Date.now());return row||null}
function logout(req){const m=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization||'');if(m)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(m[1]))}
function getRecords(uid){return db.prepare('SELECT task_id AS id,status,note,completed_at AS completedAt FROM records WHERE user_id=? ORDER BY updated_at,task_id').all(uid)}
const TASK_IDS=new Set(['care1','dig1','kind1','env1','env2','kind2','care2','dig2','care3','env3']);
function putRecords(uid,records){if(!Array.isArray(records)||records.length>10)throw Error('任務資料格式不正確');const seen=new Set();for(const r of records){if(!r||!TASK_IDS.has(r.id)||seen.has(r.id)||!['done','pending'].includes(r.status)||typeof r.note!=='string'||r.note.length>500||typeof r.completedAt!=='string'||r.completedAt.length>60)throw Error('不合法的任務紀錄');seen.add(r.id)}db.exec('BEGIN');try{db.prepare('DELETE FROM records WHERE user_id=?').run(uid);const stmt=db.prepare('INSERT INTO records(user_id,task_id,status,note,completed_at) VALUES(?,?,?,?,?)');for(const r of records)stmt.run(uid,r.id,r.status,r.note,r.completedAt);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return getRecords(uid)}
module.exports={register,login,session,logout,getRecords,putRecords};
