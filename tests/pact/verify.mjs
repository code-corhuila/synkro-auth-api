import { Verifier } from '@pact-foundation/pact';
import { createServer } from 'node:http';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';

const folder=fileURLToPath(new URL('.',import.meta.url));
const base=process.env.PROVIDER_BASE_URL;
const database=process.env.PGDATABASE;
assert.ok(base && /^synkro_auth_disposable_[a-z0-9_]+$/.test(database??''),'A disposable provider database is mandatory');
const sql=query=>execFileSync('psql',['-X','-v','ON_ERROR_STOP=1','-At','-c',query],{encoding:'utf8',timeout:20000}).trim();
assert.equal(sql('SELECT current_database()'),database,'Server identity must match the disposable database');
const provenance=JSON.parse(readFileSync(folder+'provenance.json','utf8'));
for(const item of provenance.contracts){
  const bytes=readFileSync(folder+'contracts/'+item.file,'utf8').replaceAll('\r\n','\n');
  assert.match(item.revision,/^[0-9a-f]{40}$/);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,'Consumer artifact changed');
}
const secretValues=new Set([process.env.PACT_ADMIN_PASSWORD,process.env.PGPASSWORD].filter(Boolean));
const newSecret=()=>{const value=randomBytes(24).toString('hex');secretValues.add(value);return value;};
async function request(path,body,token,key,expected=200){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
  try{
    const response=await fetch(base+path,{method:'POST',signal:controller.signal,headers:{'Content-Type':'application/json',
      ...(token?{Authorization:'Bearer '+token}:{}),...(key?{'Idempotency-Key':key}:{})},body:JSON.stringify(body)});
    assert.equal(response.status,expected,'Provider state request failed: '+path);
    const value=await response.json();
    if(value.accessToken)secretValues.add(value.accessToken);
    if(value.refreshToken)secretValues.add(value.refreshToken);
    return value;
  }finally{clearTimeout(timer);controller.abort();}
}
const credentials=await request('/api/v1/auth/login',{email:process.env.PACT_ADMIN_EMAIL,password:process.env.PACT_ADMIN_PASSWORD});
const admin=credentials.accessToken;
const actor=JSON.parse(Buffer.from(admin.split('.')[1],'base64url')).sub;
assert.match(actor,/^[a-f0-9-]{36}$/);
const contexts=new Map();
async function target(tag){
  const password=newSecret(),email='pact-'+tag+'-'+randomUUID()+'@example.test';
  const user=await request('/api/v1/auth/register',{name:'Pact '+tag,email,password,role:'SALESPERSON'},admin,randomUUID(),201);
  assert.match(user.userId,/^[a-f0-9-]{36}$/);
  return {targetId:user.userId,email,initialPassword:password,password:newSecret(),token:admin};
}
const reset=(c,key,password=c.password)=>request('/api/v1/auth/users/'+c.targetId+'/password-reset',
  {newPassword:password,confirmPassword:password},admin,key);
const count=c=>Number(sql(`SELECT count(*) FROM auth_schema.password_reset_audit WHERE target_user_id='${c.targetId}'::uuid`));
async function recorded(key,tag){
  const c=await target(tag);c.original=await reset(c,key);return c;
}
const expire=(c,key)=>sql(`UPDATE auth_schema.password_reset_receipt SET expires_at=clock_timestamp()-interval '1 second' WHERE audit_id IN (SELECT audit_id FROM auth_schema.password_reset_audit WHERE actor_user_id='${actor}'::uuid AND idempotency_key='${key}')`);
const states={
  'an active salesperson can be reset':async()=>{const c=await target('success');contexts.set('pact-auth-reset-success',c);return {targetId:c.targetId};},
  'the original reset preceded a later password change':async()=>{
    const c=await recorded('pact-auth-reset-replay','replay');c.laterPassword=newSecret();await reset(c,'pact-auth-reset-later',c.laterPassword);
    contexts.set('pact-auth-reset-replay',c);return {targetId:c.targetId};
  },
  'the reset receipt expired':async()=>{
    const c=await recorded('pact-auth-reset-expired','expired');expire(c,'pact-auth-reset-expired');
    contexts.set('pact-auth-reset-expired',c);return {targetId:c.targetId};
  },
  'the expired reset receipt was purged':async()=>{
    const c=await recorded('pact-auth-reset-purged','purged');expire(c,'pact-auth-reset-purged');
    assert.ok(Number(sql('SELECT auth_schema.purge_expired_password_reset_receipts(1000)'))>=1);
    contexts.set('pact-auth-reset-purged',c);return {targetId:c.targetId};
  },
  'the caller is a salesperson':async()=>{
    const c=await target('denied'),caller=await target('caller');
    c.token=(await request('/api/v1/auth/login',{email:caller.email,password:caller.initialPassword})).accessToken;
    contexts.set('pact-auth-reset-denied',c);return {targetId:c.targetId};
  },
};
const options={provider:'AuthAPI',pactUrls:[folder+'contracts/AuthPortal-AuthAPI.json'],logLevel:'error'};
let received=0;
const incompatible=createServer((req,res)=>{received++;req.resume();res.setHeader('Content-Type','application/json');res.end('{"wrongContract":true}');});
try{
  await new Promise(resolve=>incompatible.listen(0,'127.0.0.1',resolve));
  try{
    await assert.rejects(()=>new Verifier({...options,providerBaseUrl:'http://127.0.0.1:'+incompatible.address().port,
      stateHandlers:Object.fromEntries(Object.keys(states).map(name=>[name,async()=>({targetId:'550e8400-e29b-41d4-a716-446655440019'})]))}).verifyProvider());
    assert.ok(received>=5,'Negative control must reach the incompatible HTTP service');
    console.log('Pact negative control: incompatible Auth provider reached and rejected');
  }finally{await new Promise(resolve=>incompatible.close(resolve));}
  await new Verifier({...options,providerBaseUrl:base,stateHandlers:states,requestFilter:(req,res,next)=>{
    const c=contexts.get(req.headers['idempotency-key']);
    assert.ok(c,'Unknown contract interaction');
    req.headers.authorization='Bearer '+c.token;
    // Credentials cannot be persisted in a shared Pact. Preserve the matched body shape while injecting ephemeral input.
    req.body={...req.body,newPassword:c.password,confirmPassword:c.password};
    delete req.headers['content-length'];next();
  }}).verifyProvider();
  for(const [key,c] of contexts){
    assert.equal(count(c),key.endsWith('success')?1:key.endsWith('replay')?2:key.endsWith('denied')?0:1);
    const current=key.endsWith('replay')?c.laterPassword:key.endsWith('denied')?c.initialPassword:c.password;
    await request('/api/v1/auth/login',{email:c.email,password:current});
    if(key.endsWith('replay'))assert.equal((await reset(c,key)).passwordResetAt,c.original.passwordResetAt);
  }
  console.log('Pact provider: 5 Auth Portal interactions verified against real Auth API/PostgreSQL; replay and no-effect postconditions passed');
}catch(error){
  let message=error?.stack??String(error);
  for(const secret of secretValues)message=message.replaceAll(secret,'[REDACTED]');
  message=message.replace(/\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g,'[BCRYPT-REDACTED]');
  console.error(message);process.exitCode=1;
}
