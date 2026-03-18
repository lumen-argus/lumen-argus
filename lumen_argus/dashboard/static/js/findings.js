/* findings.js — filterable paginated table, detail panel, export */
function loadFindings(){
  var url='/api/v1/findings?limit='+findPerPage+'&offset='+findPage*findPerPage;
  var sevF=document.getElementById('f-sev').value;
  var detF=document.getElementById('f-det').value;
  var provF=document.getElementById('f-prov').value;
  if(sevF)url+='&severity='+encodeURIComponent(sevF);
  if(detF)url+='&detector='+encodeURIComponent(detF);
  if(provF)url+='&provider='+encodeURIComponent(provF);
  fetch(url).then(function(r){return r.json()}).then(function(fd){
    allFindings=fd.findings||[];findTotal=fd.total;
    renderFindingsTable();
  }).catch(function(e){showPageError('find-tbody','Failed to load findings: '+e.message,loadFindings);});}
function renderFindingsTable(){
  var thead=document.getElementById('find-thead');thead.replaceChildren();
  var vis=ALL_COLS.filter(function(c){return c.on});
  for(var i=0;i<vis.length;i++){(function(col){
    var th=document.createElement('th');th.textContent=col.label;
    var arrow=document.createElement('span');arrow.className='sort-arrow';
    arrow.textContent=sortCol===col.key?(sortAsc?'\u25b2':'\u25bc'):'\u25bc';
    if(sortCol===col.key)th.classList.add('sorted');th.appendChild(arrow);
    th.addEventListener('click',function(){if(sortCol===col.key)sortAsc=!sortAsc;
      else{sortCol=col.key;sortAsc=true;}loadFindings();});
    thead.appendChild(th);})(vis[i]);}
  document.getElementById('find-total').textContent=findTotal+' findings';
  var tbody=document.getElementById('find-tbody');tbody.replaceChildren();
  if(!allFindings.length){var tr=document.createElement('tr');var td=document.createElement('td');
    td.colSpan=vis.length;td.className='empty';td.textContent='No findings match filters';
    tr.appendChild(td);tbody.appendChild(tr);return;}
  for(var j=0;j<allFindings.length;j++){(function(f){
    var tr=document.createElement('tr');if(f.id===selectedFindingId)tr.classList.add('selected');
    for(var k=0;k<vis.length;k++){var col=vis[k];var td=document.createElement('td');
      if(col.cls)td.className=col.cls;
      if(col.key==='severity')td.appendChild(makeBadge(f.severity));
      else if(col.key==='action_taken'&&f.action_taken){var tag=document.createElement('span');
        tag.className='action-tag';tag.textContent=f.action_taken;td.appendChild(tag);}
      else if(col.key==='timestamp')td.textContent=fmtTime(f.timestamp);
      else if(col.key==='location'){td.textContent=f[col.key]||'';td.title=f[col.key]||'';}
      else td.textContent=f[col.key]!=null?String(f[col.key]):'';
      tr.appendChild(td);}
    tr.addEventListener('click',function(){showDetail(f)});
    tbody.appendChild(tr);})(allFindings[j]);}
  renderPager('find-pager',findPage,findTotal,findPerPage,
    function(pg){findPage=pg;loadFindings();},
    function(pp){findPerPage=pp;findPage=0;loadFindings();});}
function showDetail(f){selectedFindingId=f.id;
  var panel=document.getElementById('detail-panel');panel.classList.add('visible');
  document.querySelector('.findings-layout').classList.add('has-detail');
  if(window.innerWidth<=1000)setTimeout(function(){panel.scrollIntoView({behavior:'smooth',block:'start'})},50);
  var grid=document.getElementById('detail-grid');grid.replaceChildren();
  [['ID',f.id],['Timestamp',f.timestamp],['Detector',f.detector],['Type',f.finding_type],
   ['Severity',f.severity],['Action',f.action_taken||'none'],['Location',f.location],
   ['Provider',f.provider||'unknown'],['Model',f.model||'unknown'],['Preview',f.value_preview||'']
  ].forEach(function(pair){var item=document.createElement('div');item.className='detail-item';
    var lbl=document.createElement('label');lbl.textContent=pair[0];
    var val=document.createElement('div');val.className='val';val.textContent=String(pair[1]);
    item.appendChild(lbl);item.appendChild(val);grid.appendChild(item);});
  renderFindingsTable();}
document.getElementById('f-sev').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-det').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('f-prov').addEventListener('change',function(){findPage=0;loadFindings();});
document.getElementById('detail-panel-close').addEventListener('click',function(){
  document.getElementById('detail-panel').classList.remove('visible');
  document.querySelector('.findings-layout').classList.remove('has-detail');
  selectedFindingId=null;});
