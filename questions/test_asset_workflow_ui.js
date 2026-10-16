const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const elements = {}, handlers = {}, calls = [];
function element(id) { return elements[id] ||= {value:'',textContent:'',children:[],hidden:true}; }
const ctx = vm.createContext({
  $:element, on:(id,event,fn)=>{handlers[id+':'+event]=fn;},
  clear:el=>{el.children=[];}, add:(el,tag,cls,text)=>{const child={tag,textContent:text,children:[],addEventListener(){}};el.children.push(child);return child;},
  clearError(){}, showError:e=>{throw e;}, setView(){},
  api:(url,options)=>{calls.push({url,options});return Promise.resolve(url.includes('demo/evaluate') ? {demo_assets:[{is_demo:true}],risks_saved:3} : {items:[],total:0});},
  assetImpactRequestVersions:{declared:0},
  loadAssets:async()=>{}, renderAssetImpact(){}, loadRisks:async()=>{},
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
  assert.ok(calls.some(row=>row.url==='/api/assets/demo/evaluate' && row.options.method==='POST'));
  assert.equal(element('asset-demo').disabled,false);
  assert.ok(element('asset-message').textContent.includes('同步 3 条'));
  assert.ok(JSON.parse(element('asset-json').value).assets[0].is_demo);
  element('asset-entry-id').value='ai-1';element('asset-entry-name').value='service';
  element('asset-entry-vendor').value='ollama';element('asset-entry-product').value='ollama';
  element('asset-entry-exposure').value='unknown';element('asset-json').value='';
  handlers['asset-entry-form:submit']({preventDefault(){}});
  assert.equal(JSON.parse(element('asset-json').value).assets[0].asset_id,'ai-1');
  assert.ok(element('asset-entry-message').textContent.includes('尚未保存'));
  console.log('asset workflow UI: one-click persistence, bounded CycloneDX conversion, unknown identities and form staging passed');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
