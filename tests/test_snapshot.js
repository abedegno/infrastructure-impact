// Real-dataset parity matters: the hosted pilot performs comparison in-browser.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const context={window:{},Set,URL,Response,Blob};
vm.createContext(context);
vm.runInContext(fs.readFileSync('web/research-dossiers.js','utf8'),context);
vm.runInContext(fs.readFileSync('web/snapshot.js','utf8'),context);
const state=JSON.parse(fs.readFileSync('site/dist/snapshot.json','utf8'));
const compared=context.snapshotCompare(state.records,state.comparison.cohort,state.vendors,state.comparison);
assert.deepStrictEqual(JSON.parse(JSON.stringify(compared)),state.comparison);
for(const ids of [['CVE-2024-1086'],Object.keys(state.benchmark_cohort),['CVE-1999-999999']]){
 const selected=context.selectSnapshot(state,ids);
 assert.equal(selected.comparison.cohort.length,ids.length);
 assert.equal(selected.coverage.length,ids.length*Object.keys(state.vendors).length);
 if(ids.length===Object.keys(state.benchmark_cohort).length)assert(selected.coverage.every(p=>p.checks.length>0), 'Benchmark checks must survive even when a CVE has no imported advisory');
 const exported=context.exportSnapshot(selected);
 assert(exported.records.every(r=>r.assessments.every(a=>ids.includes(a.cve_id))));
 const csv=context.snapshotCSV(selected);
 assert(!csv.includes('CVE-2025-32728'));
}
const hostile={...state,records:[{...state.records[0],assessments:[{...state.records[0].assessments[0],cve_id:'CVE-2024-1086',product:'=HYPERLINK("https://example.test")'}],cves:['CVE-2024-1086']}],comparison:{cohort:['CVE-2024-1086']}};
assert(context.snapshotCSV(hostile).includes("'=HYPERLINK"));
console.log('Snapshot/Python comparison parity, cohort export isolation, coverage and CSV formula escaping passed.');
