/* Student investigations: keeps written evidence with the working simulations. */
(function(){
"use strict";
const $=id=>document.getElementById(id);
const key="security-bench-classroom-v3";
const notes={};
try{Object.assign(notes,JSON.parse(localStorage.getItem(key)||"{}"));}catch(e){}
function save(){try{localStorage.setItem(key,JSON.stringify(notes));}catch(e){}}
function add(where,html,position="beforeend"){const el=document.querySelector(where);if(!el)throw Error("Missing stage "+where);el.insertAdjacentHTML(position,html);}
function prompt(id,label,hint,rows=3){
 return '<div class="student-note"><label for="'+id+'">'+label+'</label>'+
 '<p class="activity-hint">'+hint+'</p>'+
 '<textarea id="'+id+'" rows="'+rows+'" placeholder="Write your explanation and refer to a specific result."></textarea>'+
 '<span class="save-label">Saved on this device as you type.</span></div>';
}
function wireNotes(){
 document.querySelectorAll(".student-note textarea").forEach(el=>{
   el.value=notes[el.id]||"";
   el.addEventListener("input",()=>{notes[el.id]=el.value;save();});
 });
}
function concept(id,q,options,answer,explanation){
return '<div class="case-question" id="'+id+'"><strong>'+q+'</strong><div class="case-options">'+options.map((o,i)=>'<button type="button" data-choice="'+i+'">'+o+'</button>').join("")+'</div><p class="case-feedback" role="status"></p></div>';
}
function wireConcepts(){
 document.querySelectorAll(".case-question").forEach(panel=>{
   const buttons=[...panel.querySelectorAll("button")];
   const correct=Number(panel.dataset.correct);
   buttons.forEach((b,i)=>b.addEventListener("click",()=>{
     buttons.forEach(x=>x.classList.remove("picked"));
     b.classList.add("picked");
     const isCorrect=i===correct;
     const msg=panel.querySelector(".case-feedback");
     msg.textContent=(isCorrect?"Correct. ":"Not quite. ")+panel.dataset.explain;
     msg.className="case-feedback "+(isCorrect?"pass":"fail");
   }));
 });
}
function counts(files,config){
 let tp=0,fp=0,fn=0,tn=0;
 for(const f of files){
  const sig=config.sig && KNOWN_SIGS.includes(f.sig);
  const hits=f.beh.filter(b=>config.selected.includes(b)).length;
  const flagged=sig||(config.selected.length>0&&hits>=config.threshold);
  if(f.truth==="malware")flagged?tp++:fn++;
  else flagged?fp++:tn++;
 }
 return {tp,fp,fn,tn};
}
const policyRuns=[];
function showPolicyRuns(){
 const out=$("policy-ledger");if(!out)return;
 out.innerHTML=policyRuns.length?'<table class="compare-table"><thead><tr><th>Run</th><th>Settings</th><th>Threats caught</th><th>Threats missed</th><th>Safe files blocked</th></tr></thead><tbody>'+
 policyRuns.map((r,i)=>'<tr><td>'+String.fromCharCode(65+i)+'</td><td>'+r.config.selected.length+' behaviour checks / '+r.config.threshold+' required / signatures '+(r.config.sig?"on":"off")+'</td><td>'+r.result.tp+'</td><td>'+r.result.fn+'</td><td>'+r.result.fp+'</td></tr>').join("")+'</tbody></table>':
 '<p class="activity-hint">No policies recorded yet. Run a scan above.</p>';
 const next=$("av4-next");
 if(next && policyRuns.length<2)next.disabled=true;
 if($("policy-next"))$("policy-next").textContent=policyRuns.length<2?"Test "+(2-policyRuns.length)+" more different configuration(s).":"Two different configurations tested. Explain which you prefer.";
}
function recordPolicy(){
 const config={selected:[...STATE.av.selected],threshold:STATE.av.threshold,sig:STATE.av.useSig};
 const signature=JSON.stringify(config.selected.slice().sort())+"|"+config.threshold+"|"+config.sig;
 if(policyRuns.some(r=>r.signature===signature)){const t=$("policy-next");if(t)t.textContent="Already tested this configuration. Change a rule or threshold.";showPolicyRuns();return;}
 const result=counts(AV4,config);
 policyRuns.push({config,result,signature});
 notes.policyRuns=policyRuns;save();
 showPolicyRuns();
}
function prediction(id,question,items){
 return '<fieldset class="prediction" id="'+id+'"><legend>'+question+'</legend>'+
 '<p class="activity-hint">Make a prediction BEFORE pressing scan. You will compare it with the actual evidence afterwards.</p>'+
 items.map((x,i)=>'<label><input type="checkbox" value="'+i+'"> '+x+'</label>').join("")+
 '<p class="prediction-feedback" role="status"></p></fieldset>';
}
function checkPrediction(id,expected){
 const area=$(id);if(!area)return;
 const chosen=[...area.querySelectorAll("input:checked")].map(x=>Number(x.value)).sort((a,b)=>a-b);
 const correct=expected.slice().sort((a,b)=>a-b);
 const equal=JSON.stringify(chosen)===JSON.stringify(correct);
 area.querySelector(".prediction-feedback").textContent=equal?"Your prediction matched the scan. Explain which evidence you used.":"Compare the files you selected with those detected. Which signature matches did you overlook or assume?";
}
function enhance(){
 // Investigate before clicking: students inspect recognisable file signatures.
 add('[data-screen="av1"] .panel.inset',prediction("prediction-a1","Before scanning: which files do you expect this exact-signature scanner to quarantine?",AV1.map(f=>f.name)),"beforebegin");
 $("av1-scan").addEventListener("click",()=>checkPrediction("prediction-a1",[3,5]));
 add('[data-screen="av1"] .nav',prompt("av1-reason","Explain the result","Why was invoice_update.exe missed even though it appears to be harmful?"),"beforebegin");
 add('[data-screen="av2"] .nav',concept("concept-variant","What changed about the two malware variants?",["They became harmless.","Their identifiers changed while their simulated harmful behaviours remained.","They changed the firewall port."],1,"An exact match requires the same recognised pattern. A modified file may not match the recorded identifier.")+prompt("av2-reason","Apply what you learned","Suggest one type of evidence beyond an exact signature that could help detect a variant."),"beforebegin");
 add('[data-screen="av3"] .nav',prompt("av3-reason","Interpret your first behaviour scan","Identify one malicious file detected because of its behaviour. Which warning signs caused the decision?"),"beforebegin");
 add('[data-screen="av4"] .nav',
 '<section class="policy-comparison"><h3>Policy comparison: two trials</h3><p>Test two <strong>different</strong> detector configurations on the mixed files. Compare what each catches, misses and incorrectly blocks. One scan is not sufficient evidence for a recommendation.</p><div id="policy-ledger"></div><p class="activity-hint" id="policy-next"></p></section>'+
 prompt("av4-compare","Choose a policy for a college payroll computer","State which of your two configurations you would deploy, citing at least one missed threat or false alarm. Explain the operational impact."),"beforebegin");
 $("av4-scan").addEventListener("click",recordPolicy);
 add('[data-screen="av5"] .nav',prompt("av5-reason","Unseen detector evaluation","Did your preferred policy generalise to new files? Give the detection rate, missed threats and false positives, then name a limitation that remains."),"beforebegin");
 add('[data-screen="fw2"] .nav',
 '<section class="packet-primer"><h3>Read an actual traffic record</h3><p>The simulation shows five separate pieces of information. Click a field to see why it matters.</p><table class="compare-table"><tbody><tr><th>Source</th><td><button type="button" data-explain="The device or network where the connection originated. Here it is a staff computer.">Staff workstation</button></td></tr><tr><th>Destination</th><td><button type="button" data-explain="The intended recipient: a public website, mail relay, resolver or internal server.">Public website</button></td></tr><tr><th>Direction</th><td><button type="button" data-explain="Outbound: initiated by the organisation toward a service. Inbound: arriving from outside toward an internal service.">Outbound</button></td></tr><tr><th>Protocol</th><td><button type="button" data-explain="TCP and UDP are different transport protocols. Port 53 over TCP is not the same rule as port 53 over UDP.">TCP</button></td></tr><tr><th>Destination port</th><td><button type="button" data-explain="443 is commonly used for HTTPS. The port gives a clue about traffic; it cannot prove the connection is safe.">443</button></td></tr></tbody></table><div class="packet-explanation" role="status">Select a field above to examine it.</div></section>'+
 concept("concept-packet","A rule allowing outbound TCP 443 would also allow which connection, if all its fields matched?",["Only safe websites, because 443 proves a connection is safe.","A harmful HTTPS connection with the same metadata.","Every incoming SSH connection."],1,"A firewall using only these fields cannot identify malicious intent inside otherwise permitted traffic.")+
 prompt("fw2-reason","Check understanding","In your own words, explain why a source and destination matter when defining a firewall rule."),"beforebegin");
 document.querySelectorAll(".packet-primer button").forEach(b=>b.addEventListener("click",()=>{document.querySelector(".packet-explanation").textContent=b.dataset.explain;}));
 add('[data-screen="fw3"] .bench',
 '<div class="worked-rule"><h3>A worked rule before your first attempt</h3><p>Suppose a staff computer needs to visit a website: <strong>Allow</strong> traffic from <strong>Staff</strong> to <strong>Internet</strong>, travelling <strong>outbound</strong> using <strong>TCP</strong> on port <strong>443</strong>. This grants that connection, not unrestricted network access.</p><p class="activity-hint">Your configuration must also support DNS (UDP 53), email submission (TCP 587) and approved IT administration (inbound TCP 22), while denying unauthorised incoming requests.</p></div>',"beforebegin");
 add('[data-screen="fw3"] .nav',prompt("fw3-reason","Explain one of your firewall rules","Write one complete rule including source, destination, direction, protocol, port and action. Explain why it is necessary."),"beforebegin");
 add('[data-screen="fw4"] .bench',
 '<div class="worked-rule"><h3>The inherited fault</h3><p>Rule 1 blocks <strong>all outbound connections from staff</strong>. More specific permission rules are further down. Repair the ordering without deleting the broad blocking rule; then re-test all four connections.</p></div>',"beforebegin");
 add('[data-screen="fw4"] .nav',prompt("fw4-reason","Diagnose the problem","Name the original first-matching rule and explain why moving it below the required allow rules restores services."),"beforebegin");
 add('[data-screen="fw5"] .nav',prompt("fw5-reason","Evaluate your unseen firewall traffic","Which necessary connections worked? Which were blocked? Why can a port-based policy not always distinguish harmful HTTPS from legitimate HTTPS?"),"beforebegin");
 add('[data-screen="eval"] .examq',prompt("final-evaluation","Write your own evaluation (12 marks)","Compare security and availability using measured evidence from both labs. Discuss limitations and end with a justified recommendation.",8),"afterend");
 document.querySelectorAll(".case-question").forEach((p)=>{
  p.dataset.correct=p.id==="concept-variant"||p.id==="concept-packet"?"1":"0";
  p.dataset.explain=p.id==="concept-variant"?"These are modelled variants with altered identifiers; behaviour indicators provide different evidence.":"The same destination port and protocol do not prove that traffic is safe.";
 });
 wireConcepts();wireNotes();
 if(Array.isArray(notes.policyRuns)){policyRuns.push(...notes.policyRuns);showPolicyRuns();}
 else showPolicyRuns();
 // Each navigation to the assessment recomputes measurements without writing a model answer.
 const existingGo=window.go;
 window.go=function(i){existingGo(i);if(i===12)setTimeout(updateEvidence,0);};
 const originalScore=$("evidence");
 function updateEvidence(){
   if(!originalScore)return;
   let raw=originalScore.value.split("MY EXPLANATION AND JUDGEMENT:")[0];
   const responses=[["SIGNATURE INVESTIGATION","av1-reason"],["MALWARE VARIANTS","av2-reason"],["HEURISTIC ANALYSIS","av3-reason"],["COMPARISON OF TWO POLICIES","av4-compare"],["UNSEEN ANTIVIRUS REVIEW","av5-reason"],["PACKET FIELDS","fw2-reason"],["FIREWALL RULE RATIONALE","fw3-reason"],["RULE ORDER TROUBLESHOOTING","fw4-reason"],["UNSEEN FIREWALL REVIEW","fw5-reason"],["FINAL AO3 EVALUATION","final-evaluation"]];
   originalScore.value=raw+"\n\nSTUDENT WRITTEN EVIDENCE\n"+responses.map(([heading,id])=>heading+"\n"+(notes[id]||"(not completed)")).join("\n\n");
 }
 $("copy-ev").addEventListener("click",updateEvidence,true);
 $("dl-ev").addEventListener("click",updateEvidence,true);
 if($("final-evaluation"))$("final-evaluation").addEventListener("input",updateEvidence);
}
document.addEventListener("DOMContentLoaded",enhance);
})();