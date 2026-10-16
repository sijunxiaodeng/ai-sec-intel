const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = {}, handlers = {}, calls = [];
let demoGate, demoFailure, refreshFailure;
function element(id) { return elements[id] ||= {value:'',textContent:'',children:[],hidden:true,
  setAttribute(key,value){this[key]=value;}, removeAttribute(key){delete this[key];}}; }
const ctx = vm.createContext({
  $:element, on:(id,event,fn)=>{handlers[id+':'+event]=fn;},
  clear:el=>{el.children=[];}, add:(el,tag,cls,text)=>{const child={tag,textContent:text,children:[],addEventListener(){}};el.children.push(child);return child;},
  clearError(){}, showError:e=>{throw e;}, setView(){},
  api:async(url,options)=>{calls.push({url,options});
    if (!url.includes('demo/match')) return {items:[],total:0};
    if (demoGate) await demoGate;
    if (demoFailure) throw demoFailure;
    return {demo_assets:[{name:'Old component',is_demo:true},{name:'Unknown version',is_demo:true},{name:'Boundary',is_demo:true}],risks_saved:6};
  },
  assetImpactRequestVersions:{declared:0},
  loadAssets:async()=>{}, renderAssetImpact(report,target){calls.push({render:target || element('asset-impact'),report});},
  loadRisks:async()=>{if(refreshFailure) throw refreshFailure;},
  assetPayload:()=>JSON.parse(element('asset-json').value),
});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../web/asset-workflow.js'),'utf8'),ctx);
const parse=text=>ctx.parseAssetInventoryFile(JSON.stringify(text));
async function main(){
  const original={assets:[{asset_id:'existing'}]};
  assert.equal(parse(original).payload.assets[0].asset_id,'existing');
  let result=parse({bomFormat:'CycloneDX',components:[{name:'ollama',version:'0.1.33',purl:'pkg:pypi/ollama@0.1.33'},{name:'unknown'}]});
  assert.equal(result.payload.assets.length,1);
  assert.equal(result.payload.assets[0].vendor,'ollama');
  assert.ok(result.notice.includes('1 条缺少'));
  result=parse({bomFormat:'CycloneDX',components:[{name:'service',version:'1.0',cpe:'cpe:2.3:a:vendor:component:1.0:*:*:*:*:linux:*:*'}]});
  assert.equal(result.payload.assets[0].qualifiers.target_sw,'linux');
  assert.throws(()=>parse({bomFormat:'CycloneDX',components:[{name:'ollama',purl:'pkg:npm/ollama@1.0'}]}),/未找到/);
  assert.throws(()=>parse({bomFormat:'CycloneDX',components:[{name:'ollama',version:'2.0',cpe:'cpe:2.3:a:ollama:ollama:1.0:*:*:*:*:*:*:*'}]}),/未找到/);
  await ctx.runAssetDemo(element('asset-demo'));
  assert.ok(calls.some(row=>row.url==='/api/assets/demo/match' && row.options.method==='POST'));
  assert.equal(element('asset-demo').disabled,false);
  assert.ok(element('asset-message').textContent.includes('共有 6 条 CVE 关联'));
  assert.ok(JSON.parse(element('asset-json').value).assets[0].is_demo);
  element('risk-demo').textContent='载入并评估演示';
  element('asset-demo').textContent='载入并评估演示';
  element('risks').hidden=false;
  let releaseDemo;
  demoGate=new Promise(resolve=>{releaseDemo=resolve;});
  const pending=ctx.runAssetDemo(element('risk-demo'));
  assert.equal(element('risk-demo-message').hidden,false,'progress must be visible on the risk page');
  assert.ok(element('risk-demo-message').textContent.includes('正在保存'));
  assert.equal(element('risk-demo').disabled,true);
  assert.equal(element('risk-demo')['aria-busy'],'true');
  assert.ok(element('risk-demo').textContent.includes('正在载入'));
  const requestCount=calls.filter(row=>row.url==='/api/assets/demo/match').length;
  await ctx.runAssetDemo(element('asset-demo'));
  assert.equal(calls.filter(row=>row.url==='/api/assets/demo/match').length,requestCount,'busy controls must not submit twice');
  releaseDemo(); await pending; demoGate=null;
  assert.ok(element('risk-demo-message').textContent.includes('点击下方组件'));
  assert.ok(element('risk-demo-message').textContent.includes('关联总数可能不变'));
  assert.equal(element('risk-demo-result').hidden,false);
  assert.ok(element('risk-demo-impact').textContent.includes('Old component'));
  assert.ok(!element('risk-demo-message').textContent.includes('CVE-2024-37032'),'the component demo must not be presented as a single-CVE assessment');
  assert.equal(element('risk-demo').textContent,'载入并评估演示');
  assert.equal(element('risk-demo')['aria-busy'],undefined);
  demoFailure=Error('连接中断');
  await assert.rejects(ctx.runAssetDemo(element('risk-demo')),/连接中断/);
  assert.ok(element('risk-demo-message').textContent.includes('连接中断'));
  assert.equal(element('risk-demo-message').hidden,false);
  assert.equal(element('risk-demo-result').hidden,true,'old success details must not describe a failed new attempt');
  assert.equal(element('risk-demo').disabled,false);
  demoFailure=null; refreshFailure=Error('列表读取失败');
  await assert.rejects(ctx.runAssetDemo(element('risk-demo')),/列表读取失败/);
  assert.ok(element('risk-demo-message').textContent.includes('演示评估已保存'),'a read failure must not imply that the saved assessment was rolled back');
  assert.equal(element('risk-demo-result').hidden,false);
  assert.equal(element('risk-demo').disabled,false);
  refreshFailure=null;
  element('asset-entry-id').value='ai-1';element('asset-entry-name').value='service';
  element('asset-entry-vendor').value='ollama';element('asset-entry-product').value='ollama';
  element('asset-entry-exposure').value='unknown';element('asset-json').value='';
  handlers['asset-entry-form:submit']({preventDefault(){}});
  assert.equal(JSON.parse(element('asset-json').value).assets[0].asset_id,'ai-1');
  assert.ok(element('asset-entry-message').textContent.includes('尚未保存'));
  console.log('asset workflow UI: visible progress/results/errors, duplicate-submit protection, saved-result refresh errors, persistence and inventory conversion passed');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
