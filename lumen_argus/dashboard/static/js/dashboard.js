/* dashboard.js — stats cards, trend chart, recent findings */
function makeBadge(sev){var b=document.createElement('span');b.className='badge '+sevCls(sev);
  var d=document.createElement('span');d.className='badge-dot';b.appendChild(d);
  var t=document.createElement('span');t.textContent=sev;b.appendChild(t);return b;}
function makeCard(sev,count){var c=document.createElement('div');c.className='card '+sevCls(sev);
  var top=document.createElement('div');top.className='card-top';
  var lbl=document.createElement('div');lbl.className='card-label';lbl.textContent=sev;
  var ic=document.createElement('div');ic.className='card-icon';
  /* Static SVG icon constant — NOT user data, safe for innerHTML */
  ic.innerHTML=ICONS[sevCls(sev)]||ICONS.info;
  top.appendChild(lbl);top.appendChild(ic);
  var v=document.createElement('div');v.className='card-value';v.textContent=String(count);
  c.appendChild(top);c.appendChild(v);return c;}
function renderChart(daily){var svg=document.getElementById('chart');
  while(svg.firstChild)svg.removeChild(svg.firstChild);
  var W=600,H=130,pB=16,pT=4,n=daily.length;if(n<2)return;
  var mx=0;for(var i=0;i<n;i++){if(daily[i].count>mx)mx=daily[i].count;}if(!mx)mx=1;
  for(var g=0;g<4;g++){var gy=pT+(H-pT-pB)*(g/3);
    var l=document.createElementNS('http://www.w3.org/2000/svg','line');
    l.setAttribute('x1',0);l.setAttribute('x2',W);l.setAttribute('y1',gy);l.setAttribute('y2',gy);
    l.setAttribute('class','chart-grid');svg.appendChild(l);}
  var pts=[];for(var j=0;j<n;j++){pts.push((W*(j/(n-1)))+','+(pT+(H-pT-pB)*(1-daily[j].count/mx)));}
  var area=document.createElementNS('http://www.w3.org/2000/svg','polygon');
  area.setAttribute('points',pts.join(' ')+' '+W+','+(H-pB)+' 0,'+(H-pB));
  area.setAttribute('class','chart-area');svg.appendChild(area);
  var pl=document.createElementNS('http://www.w3.org/2000/svg','polyline');
  pl.setAttribute('points',pts.join(' '));pl.setAttribute('class','chart-line');svg.appendChild(pl);
  for(var k=Math.max(0,n-3);k<n;k++){var pp=pts[k].split(',');
    var ci=document.createElementNS('http://www.w3.org/2000/svg','circle');
    ci.setAttribute('cx',pp[0]);ci.setAttribute('cy',pp[1]);ci.setAttribute('class','chart-dot');svg.appendChild(ci);}
  [0,Math.floor(n/2),n-1].forEach(function(li,m){var lx=W*(li/(n-1));
    var tx=document.createElementNS('http://www.w3.org/2000/svg','text');
    tx.setAttribute('x',lx);tx.setAttribute('y',H-2);tx.setAttribute('class','chart-label');
    tx.setAttribute('text-anchor',m===0?'start':m===2?'end':'middle');
    tx.textContent=(daily[li].date||'').slice(5);svg.appendChild(tx);});}
function renderBars(elId,data){var el=document.getElementById(elId);el.replaceChildren();
  var ent=[];for(var k in data){if(data.hasOwnProperty(k))ent.push({n:k,c:data[k]});}
  ent.sort(function(a,b){return b.c-a.c});var top=ent.slice(0,6);var mx=top.length?top[0].c:1;
  for(var i=0;i<top.length;i++){var row=document.createElement('div');row.className='det-row';
    var nm=document.createElement('span');nm.className='det-name';nm.textContent=top[i].n;
    var bg=document.createElement('div');bg.className='det-bar-bg';
    var bar=document.createElement('div');bar.className='det-bar';
    bar.style.width=Math.max(4,Math.round(top[i].c/mx*100))+'%';bg.appendChild(bar);
    var ct=document.createElement('span');ct.className='det-count';ct.textContent=String(top[i].c);
    row.appendChild(nm);row.appendChild(bg);row.appendChild(ct);el.appendChild(row);}
  if(!top.length){var em=document.createElement('div');em.className='empty';em.textContent='no data yet';el.appendChild(em);}}
function dashRow(f){var tr=document.createElement('tr');
  var cols=[fmtTime(f.timestamp),f.detector,f.finding_type,f.severity,f.action_taken||'\u2014',f.location];
  for(var i=0;i<cols.length;i++){var td=document.createElement('td');
    if(i===0)td.className='col-time';else if(i===2)td.className='col-type';
    else if(i===5){td.className='col-loc';td.title=cols[i];}
    if(i===3)td.appendChild(makeBadge(cols[i]));
    else if(i===4&&f.action_taken){var tag=document.createElement('span');tag.className='action-tag';tag.textContent=cols[i];td.appendChild(tag);}
    else td.textContent=cols[i];
    tr.appendChild(td);}return tr;}
function initColToggles(){var el=document.getElementById('col-toggle');el.replaceChildren();
  for(var i=0;i<ALL_COLS.length;i++){(function(idx){
    var btn=document.createElement('div');btn.className='col-btn'+(ALL_COLS[idx].on?' on':'');
    btn.textContent=ALL_COLS[idx].label;
    btn.addEventListener('click',function(){ALL_COLS[idx].on=!ALL_COLS[idx].on;
      btn.classList.toggle('on');renderFindingsTable();});
    el.appendChild(btn);})(i);}}
