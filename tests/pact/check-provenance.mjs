import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const folder=new URL('.',import.meta.url);
const source=process.argv[2];
assert.ok(source,'The pinned consumer checkout is required');
const revision=execFileSync('git',['-C',source,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
assert.equal(execFileSync('git',['-C',source,'status','--porcelain'],{encoding:'utf8'}).trim(),'','Consumer checkout is dirty');
if(process.env.AUTH_PORTAL_REF)assert.equal(revision,process.env.AUTH_PORTAL_REF);
const hash=value=>createHash('sha256').update(value.replaceAll('\r\n','\n')).digest('hex');
for(const item of JSON.parse(readFileSync(new URL('provenance.json',folder),'utf8')).contracts){
  assert.equal(item.repository,'code-corhuila/synkro-auth-portal');
  assert.equal(revision,item.revision,'Consumer pin and provenance differ');
  const original=execFileSync('git',['-C',source,'show',revision+':'+item.path],{encoding:'utf8'});
  assert.equal(hash(original),item.sha256,'Source artifact digest differs');
  assert.equal(hash(readFileSync(new URL('contracts/'+item.file,folder),'utf8')),item.sha256,'Copied artifact digest differs');
}
console.log('Auth consumer provenance verified against the pinned clean source checkout');
