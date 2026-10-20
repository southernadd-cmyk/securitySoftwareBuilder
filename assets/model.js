/* Accurate, intentionally bounded teaching model: metadata rule matching. */
(function(){
"use strict";
const practice=[
["Staff access the college portal","staff","internet","out","TCP",443,true],
["Staff make a DNS lookup","staff","resolver","out","UDP",53,true],
["Staff submit outgoing mail","staff","mail","out","TCP",587,true],
["Authorised IT connect to a server","it","server","in","TCP",22,true],
["Unknown external host probes SSH","external","server","in","TCP",22,false],
["Unknown external host probes RDP","external","server","in","TCP",3389,false]
];
function packet(r){return {what:r[0],src:r[1],dst:r[2],dir:r[3],proto:r[4],port:r[5],legit:r[6]};}
PRACTICE_TRAFFIC.splice(0,PRACTICE_TRAFFIC.length,...practice.map(packet),{
 what:"Malware uses allowed HTTPS",src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443,legit:false,note:true,
 noteText:"This has exactly the same five fields as legitimate web traffic. No rule using only these fields can tell them apart. Real organisations require additional detection."
});
UNSEEN_TRAFFIC.splice(0,UNSEEN_TRAFFIC.length,...[
 ["Staff open a web application","staff","internet","out","TCP",443,true],
 ["Staff ask the DNS resolver","staff","resolver","out","UDP",53,true],
 ["Staff submit outgoing email","staff","mail","out","TCP",587,true],
 ["Authorised administrator connects to server","it","server","in","TCP",22,true],
 ["External visitor attempts SSH","external","server","in","TCP",22,false],
 ["Outside scanner attempts RDP","external","server","in","TCP",3389,false],
 ["Staff PC tries an unexpected external SSH connection","staff","internet","out","TCP",22,false]
].map(packet),{
 what:"Infected staff device communicates over HTTPS",src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443,legit:false,note:true,
 noteText:"This encrypted session matches the ordinary HTTPS rule. In this model the firewall cannot identify the malicious intent."
});
FW4_START.splice(0,FW4_START.length,
 {action:"deny",src:"staff",dst:"*",dir:"out",proto:"*",port:"*",key:"broad-deny"},
 {action:"allow",src:"staff",dst:"internet",dir:"out",proto:"TCP",port:443,key:"https"},
 {action:"allow",src:"staff",dst:"resolver",dir:"out",proto:"UDP",port:53,key:"dns"},
 {action:"allow",src:"staff",dst:"mail",dir:"out",proto:"TCP",port:587,key:"smtp"},
 {action:"deny",src:"external",dst:"server",dir:"in",proto:"TCP",port:22,key:"ssh"}
);
FW4_TRAFFIC.splice(0,FW4_TRAFFIC.length,...[
 ["Staff opening website","staff","internet","out","TCP",443,true],
 ["Staff DNS query","staff","resolver","out","UDP",53,true],
 ["Staff submitting email","staff","mail","out","TCP",587,true],
 ["External SSH attempt","external","server","in","TCP",22,false]
].map(packet));
SERVICES.smtp.port=587;
SERVICES.smtp.label="Email submission (SMTP)";
SERVICES.smtp.desc="Clients often submit outbound mail through authenticated SMTP on TCP 587.";
function selector(id,label,options){
return '<label class="mini-field">'+label+'<select id="'+id+'">'+options.map(x=>'<option value="'+x[0]+'">'+x[1]+'</option>').join("")+'</select></label>';
}
for(const prefix of ["rb","rb4"]){
 const ref=document.getElementById(prefix+"-service");
 if(!ref)throw Error("Missing service selector "+prefix);
 ref.insertAdjacentHTML("afterend",
 selector(prefix+"-source","Source",[["staff","Staff"],["it","Authorised IT"],["external","Outside"],["*","Any"]])+
 selector(prefix+"-target","Destination",[["internet","Internet"],["resolver","DNS resolver"],["mail","Mail relay"],["server","College server"],["*","Any"]])+
 selector(prefix+"-dir","Direction",[["out","Outbound"],["in","Inbound"]])+
 selector(prefix+"-proto","Protocol",[["TCP","TCP"],["UDP","UDP"]])
 );
}
const oldBuildEval=window.buildEval;
window.buildEval=function(){
 oldBuildEval();
 const av=STATE.av.unseen;
 const fw=STATE.fw.unseen;
 const rules=STATE.fw.rules;
 const rows=[
 "SECURITY BENCH — EVIDENCE RECORDED DURING MY TESTS",
 "",
 "ANTIVIRUS RESULTS",
 av?"Malware detected: "+av.tp+"; malware missed: "+av.fn+"; safe files allowed: "+av.tn+"; false positives: "+av.fp:"Unseen antivirus test not completed",
 "Signature detection "+(STATE.av.useSig?"enabled":"disabled")+", warning threshold "+STATE.av.threshold,
 "Behaviours selected: "+[...STATE.av.selected].map(k=>BEHAVIOURS[k].label).join("; "),
 "",
 "FIREWALL RESULTS",
 fw?"Legitimate connections working: "+fw.work+"; legitimate connections blocked: "+fw.disr+"; unwanted connections blocked: "+fw.stop+"; unwanted connections permitted: "+fw.breach:"Unseen firewall test not completed",
 "Firewall rules checked in this order:",
 ...rules.map((r,i)=>(i+1)+". "+r.action.toUpperCase()+" from "+(r.src||"any")+" to "+(r.dst||"any")+" / "+r.dir+" / "+r.proto+" / "+r.port),
 "",
 "STUDENT WRITTEN EVIDENCE"
 ];
 document.getElementById("evidence").value=rows.join("\n");
};
document.addEventListener("DOMContentLoaded",()=>{
 // Align the explanation with the actual simulated outage.
 const p=document.querySelector('[data-screen="fw4"] .teach');
 if(p)p.innerHTML='<p>A colleague has placed a very broad block above the specific permissions. <strong>All three essential staff services have stopped working.</strong> Run the traffic to find the first matching rule, then fix the order without removing the broad block. This is a rule-priority fault, not a damaged network connection.</p>';
 const h=document.querySelector("#fw4-after .ch");if(h)h.textContent="Rule order corrected";
 const fw=document.querySelector('[data-screen="fw2"] .teach');
 if(fw)fw.insertAdjacentHTML("beforeend",'<p><strong>Source and destination.</strong> A rule should say who is initiating traffic and where it is going. Allowing authorised IT to reach the server is different from allowing an unknown outside computer to reach the same server. You will configure both fields yourself.</p>');
 const quote=document.querySelector('[data-screen="eval"] .teach:nth-of-type(2)');
 if(quote)quote.querySelector("p").textContent="Your tests illustrate that each security tool makes different decisions. Neither set of measurements proves protection against every threat. Use your own evidence to argue for a proportionate combination of controls.";
});
})();