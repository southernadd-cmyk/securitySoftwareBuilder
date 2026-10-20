import fs from "node:fs";
import vm from "node:vm";
import assert from "node:assert/strict";
const html=fs.readFileSync("index.html","utf8");
const inline=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m=>m[1]).filter(Boolean);
assert.equal(inline.length,1,"One inline application script expected");
for(const [name,code] of [["main",inline[0]],["model",fs.readFileSync("assets/model.js","utf8")],["learning",fs.readFileSync("assets/learning.js","utf8")]]){
 new vm.Script(code,{filename:name});
 console.log("Syntax valid:",name);
}
assert.match(html,/src="assets\/model\.js"/);
assert.match(html,/src="assets\/learning\.js"/);
assert.match(html,/href="assets\/rework\.css"/);
assert.ok(html.indexOf('assets/model.js')<html.indexOf('assets/learning.js'),"Model must initialise before lessons");
const fn=inline[0].match(/function fwEval\(pkt,rules\)\{[\s\S]*?\n\}/);
assert.ok(fn,"Five-field firewall engine present");
const evaluate=vm.runInNewContext(fn[0]+"\nfwEval");
const rules=[
 {action:"deny",src:"external",dst:"server",dir:"in",proto:"TCP",port:22},
 {action:"allow",src:"it",dst:"server",dir:"in",proto:"TCP",port:22},
 {action:"allow",src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443}
];
function check(pkt,want,description){
 const got=evaluate(pkt,rules).action;
 assert.equal(got,want,description);
}
check({src:"external",dst:"server",dir:"in",proto:"TCP",port:22},"deny","Outside blocked");
check({src:"it",dst:"server",dir:"in",proto:"TCP",port:22},"allow","IT allowed");
check({src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443},"allow","Browsing allowed");
check({src:"staff",dst:"server",dir:"in",proto:"TCP",port:22},"deny","Wrong source blocked");
check({src:"staff",dst:"internet",dir:"out",proto:"UDP",port:443},"deny","Wrong protocol blocked");
check({src:"staff",dst:"internet",dir:"in",proto:"TCP",port:443},"deny","Wrong direction blocked");
check({src:"staff",dst:"server",dir:"out",proto:"TCP",port:443},"deny","Wrong destination blocked");
const broad={action:"deny",src:"staff",dst:"*",dir:"out",proto:"*",port:"*"};
const permit={action:"allow",src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443};
const packet={src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443};
assert.equal(evaluate(packet,[broad,permit]).action,"deny","Broad deny first wins");
assert.equal(evaluate(packet,[permit,broad]).action,"allow","Specific allow first wins");
console.log("9 firewall matching and rule-order checks passed");
