/* notifications.js — notification channels page (freemium-aware, source-aware) */
var notifTypes={};var editingChannelId=null;var channelLimit=1;var channelCount=0;
function loadNotifications(){
  Promise.all([
    fetch('/api/v1/notifications/channels').then(function(r){return r.json()}),
    fetch('/api/v1/notifications/types').then(function(r){return r.json()})
  ]).then(function(res){
    var chData=res[0],typeData=res[1];
    notifTypes=typeData.types||{};
    channelLimit=typeData.channel_limit;
    channelCount=typeData.channel_count||0;
    if(chData.notifications_unavailable){
      _showUnavailable(chData.message||'');
      /* Still render any YAML channels that exist in DB */
      if(chData.channels&&chData.channels.length){
        _renderChannels(chData.channels,true);
      }
      return;
    }
    _populateTypeSelect();_updateLimitDisplay();
    _renderChannels(chData.channels||[],false);
  }).catch(function(e){showPageError('notif-channels','Failed to load: '+e.message,loadNotifications);});
}
function _showUnavailable(message){
  var el=document.getElementById('notif-unavailable');el.style.display='block';
  el.replaceChildren();
  var banner=document.createElement('div');banner.className='panel';
  banner.style.cssText='padding:14px 18px;margin-bottom:16px;border-left:3px solid var(--warning)';
  var title=document.createElement('div');
  title.style.cssText='font-weight:600;margin-bottom:6px;color:var(--warning)';
  title.textContent='Notification dispatch unavailable';
  var desc=document.createElement('div');desc.style.cssText='font-size:.82rem;color:var(--text-secondary)';
  desc.textContent=message||'Notification dispatch requires the published package.';
  var codeWrap=document.createElement('div');codeWrap.style.cssText='margin-top:8px';
  var code=document.createElement('code');code.style.cssText='font-size:.82rem;padding:2px 6px;background:var(--bg-card);border-radius:3px';
  code.textContent='pip install lumen-argus';
  codeWrap.appendChild(code);
  var hint=document.createElement('div');hint.style.cssText='font-size:.75rem;color:var(--text-muted);margin-top:6px';
  hint.textContent='YAML-configured channels are shown below but will not dispatch until the published package is installed.';
  banner.appendChild(title);banner.appendChild(desc);banner.appendChild(codeWrap);banner.appendChild(hint);
  el.appendChild(banner);
  document.getElementById('notif-add-btn').style.display='none';
  document.getElementById('notif-enable-all').style.display='none';
  document.getElementById('notif-disable-all').style.display='none';
  document.getElementById('notif-delete-all').style.display='none';
  document.getElementById('notif-limit').textContent='';
}
function _updateLimitDisplay(){
  var el=document.getElementById('notif-limit');
  var btn=document.getElementById('notif-add-btn');
  if(channelLimit===null||channelLimit===undefined){el.textContent='';btn.classList.remove('disabled');btn.title='';
    document.getElementById('notif-upgrade').style.display='none';return;}
  el.textContent=channelCount+'/'+channelLimit;
  if(channelCount>=channelLimit){btn.classList.add('disabled');btn.title='Channel limit reached';}
  else{btn.classList.remove('disabled');btn.title='';document.getElementById('notif-upgrade').style.display='none';}
}
var _upgradeTimer=null;
function _showUpgradePrompt(){
  var el=document.getElementById('notif-upgrade');
  if(el.style.display==='block'){return;}
  el.style.display='block';el.replaceChildren();
  var banner=document.createElement('div');banner.className='panel';
  banner.style.cssText='padding:14px 18px;margin-top:12px;border-left:3px solid var(--accent);opacity:0;transition:opacity .3s ease';
  var title=document.createElement('div');
  title.style.cssText='font-weight:600;font-size:.82rem;margin-bottom:4px;color:var(--accent)';
  title.textContent='Channel limit reached';
  var desc=document.createElement('div');
  desc.style.cssText='font-size:.78rem;color:var(--text-secondary);line-height:1.5';
  desc.textContent='Upgrade to Pro for Slack, Teams, PagerDuty, Email, OpsGenie, Jira \u2014 unlimited channels with reliable delivery.';
  banner.appendChild(title);banner.appendChild(desc);el.appendChild(banner);
  requestAnimationFrame(function(){banner.style.opacity='1';});
  if(_upgradeTimer)clearTimeout(_upgradeTimer);
  _upgradeTimer=setTimeout(function(){
    banner.style.opacity='0';
    setTimeout(function(){el.style.display='none';_upgradeTimer=null;},300);
  },12000);
}
function _populateTypeSelect(){
  var sel=document.getElementById('notif-type');sel.replaceChildren();
  var def=document.createElement('option');def.value='';def.textContent='Select type\u2026';sel.appendChild(def);
  for(var t in notifTypes){if(notifTypes.hasOwnProperty(t)){
    var o=document.createElement('option');o.value=t;o.textContent=notifTypes[t].label;sel.appendChild(o);}}
}
document.getElementById('notif-type').addEventListener('change',function(){
  var t=this.value;var container=document.getElementById('notif-type-fields');container.replaceChildren();
  if(!t||!notifTypes[t])return;
  var fields=notifTypes[t].fields;
  for(var key in fields){if(fields.hasOwnProperty(key)&&key!=='min_severity'){
    var f=fields[key];var row=document.createElement('div');row.className='form-row';
    var lbl=document.createElement('label');lbl.textContent=f.label+(f.required?' *':'');
    var inp;
    if(f.type==='boolean'){
      inp=document.createElement('select');inp.setAttribute('data-field',key);
      var y=document.createElement('option');y.value='true';y.textContent='Yes';
      var n=document.createElement('option');n.value='false';n.textContent='No';
      inp.appendChild(y);inp.appendChild(n);
    }else{
      inp=document.createElement('input');inp.setAttribute('data-field',key);
      inp.type=f.type==='password'?'password':(f.type==='number'?'number':'text');
      if(f.placeholder)inp.placeholder=f.placeholder;
    }
    var errMsg=document.createElement('div');errMsg.className='field-error-msg';
    errMsg.setAttribute('data-error-for',key);
    var hintEl=null;
    if(f.hint){hintEl=document.createElement('div');
      hintEl.style.cssText='font-size:.68rem;color:var(--text-muted);width:100%;padding-left:80px;margin-top:-2px';
      hintEl.textContent=f.hint;}
    inp.addEventListener('input',function(){
      this.classList.remove('field-error');
      var r=this.closest('.form-row');if(r)r.classList.remove('shake');
      var em=r&&r.querySelector('.field-error-msg');if(em)em.classList.remove('visible');
      var ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';
    });
    row.appendChild(lbl);row.appendChild(inp);
    if(hintEl)row.appendChild(hintEl);
    row.appendChild(errMsg);container.appendChild(row);
  }}
  this.classList.remove('field-error');
  var ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';
});
function _renderChannels(channels,readOnly){
  var el=document.getElementById('notif-channels');el.replaceChildren();
  _apiChannelIds=channels.filter(function(c){return c.source!=='yaml';}).map(function(c){return c.id;});
  if(!channels.length){var empty=document.createElement('div');empty.className='empty';
    empty.textContent='No notification channels configured. Add one to get started.';
    el.appendChild(empty);return;}
  channels.forEach(function(ch){
    var card=document.createElement('div');card.className='panel';
    card.style.cssText='margin-bottom:10px;padding:14px 18px';
    var hdr=document.createElement('div');hdr.style.cssText='display:flex;align-items:center;justify-content:space-between;margin-bottom:8px';
    var left=document.createElement('div');
    var nameEl=document.createElement('span');nameEl.style.cssText='font-weight:600;margin-right:12px';nameEl.textContent=ch.name;
    left.appendChild(nameEl);
    if(ch.source==='yaml'){var badge=document.createElement('span');badge.className='badge info';badge.textContent='YAML';left.appendChild(badge);}
    var typeBadge=document.createElement('span');typeBadge.className='badge '+(ch.enabled?'info':'');
    typeBadge.textContent=(notifTypes[ch.type]||{}).label||ch.type;left.appendChild(typeBadge);
    var right=document.createElement('div');right.style.cssText='display:flex;gap:6px;align-items:center';
    var dotColor='var(--warning)';var statusLabel='No sends';
    if(!ch.enabled){dotColor='var(--text-muted)';statusLabel='Disabled';}
    else if(ch.last_status==='sent'){dotColor='var(--accent)';statusLabel='Sent '+(typeof fmtTime==='function'?fmtTime(ch.last_status_at):'');}
    else if(ch.last_status==='failed'){dotColor='var(--critical)';statusLabel='Failed '+(typeof fmtTime==='function'?fmtTime(ch.last_status_at):'');}
    var dot=document.createElement('span');
    dot.style.cssText='display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;background:'+dotColor;
    var statusTxt=document.createElement('span');statusTxt.style.cssText='font-size:.75rem;color:var(--text-secondary);margin-right:8px';
    statusTxt.textContent=statusLabel;
    if(ch.last_status==='failed'&&ch.last_error)statusTxt.title=ch.last_error;
    right.appendChild(dot);right.appendChild(statusTxt);
    if(!readOnly){
      if(ch.source!=='yaml'){
        var editBtn=document.createElement('div');editBtn.className='btn btn-sm';editBtn.textContent='Edit';
        editBtn.style.cssText='font-size:.72rem;padding:3px 10px';
        editBtn.addEventListener('click',(function(id){return function(){_editChannel(id)};})(ch.id));
        right.appendChild(editBtn);}
      var testBtn=document.createElement('div');testBtn.className='btn btn-sm';testBtn.textContent='Test';
      testBtn.style.cssText='font-size:.72rem;padding:3px 10px';
      testBtn.addEventListener('click',(function(id){return function(){_testChannel(id)};})(ch.id));
      right.appendChild(testBtn);
      var togBtn=document.createElement('div');togBtn.className='btn btn-sm';
      togBtn.textContent=ch.enabled?'Disable':'Enable';
      togBtn.style.cssText='font-size:.72rem;padding:3px 10px';
      togBtn.addEventListener('click',(function(id,enabled){return function(){_toggleChannel(id,!enabled)};})(ch.id,ch.enabled));
      right.appendChild(togBtn);
      if(ch.source!=='yaml'){
        var delBtn=document.createElement('div');delBtn.className='btn btn-sm btn-danger';delBtn.textContent='Delete';
        delBtn.style.cssText='font-size:.72rem;padding:3px 10px';
        delBtn.addEventListener('click',(function(id){return function(){if(confirm('Delete this channel?'))_deleteChannel(id);};})(ch.id));
        right.appendChild(delBtn);}
    }
    hdr.appendChild(left);hdr.appendChild(right);card.appendChild(hdr);
    var cfg=ch.config_masked||{};
    if(Object.keys(cfg).length){
      var cfgRow=document.createElement('div');cfgRow.style.cssText='font-family:var(--font-data);font-size:.75rem;color:var(--text-muted);display:flex;flex-wrap:wrap;gap:6px 16px';
      for(var k in cfg){if(cfg.hasOwnProperty(k)){
        var pair=document.createElement('span');
        var kSpan=document.createElement('span');kSpan.style.color='var(--text-secondary)';kSpan.textContent=k+': ';
        var vSpan=document.createElement('span');vSpan.textContent=typeof cfg[k]==='object'?JSON.stringify(cfg[k]):String(cfg[k]);
        pair.appendChild(kSpan);pair.appendChild(vSpan);cfgRow.appendChild(pair);}}
      card.appendChild(cfgRow);}
    var testResult=document.createElement('div');testResult.id='notif-test-'+ch.id;
    testResult.style.cssText='font-family:var(--font-data);font-size:.75rem;margin-top:6px';
    card.appendChild(testResult);el.appendChild(card);
  });
}
function _testChannel(id){
  var el=document.getElementById('notif-test-'+id);if(!el)return;
  el.style.color='var(--text-secondary)';el.textContent='Sending test\u2026 0s';
  var startTime=Date.now();
  var timer=setInterval(function(){
    var elapsed=Math.round((Date.now()-startTime)/1000);
    if(elapsed>=15){clearInterval(timer);el.style.color='var(--critical)';el.textContent='Test timed out (15s)';return;}
    el.textContent='Sending test\u2026 '+elapsed+'s';
  },1000);
  fetch('/api/v1/notifications/channels/'+id+'/test',{method:'POST',headers:csrfHeaders()}).then(function(r){return r.json()}).then(function(res){
    clearInterval(timer);
    if(res.status==='sent'){el.style.color='var(--accent)';el.textContent='Test sent successfully';}
    else{el.style.color='var(--critical)';el.textContent='Test failed: '+(res.error||'unknown error');}
  }).catch(function(e){clearInterval(timer);el.style.color='var(--critical)';el.textContent='Test failed: '+e.message;});
}
function _editChannel(id){
  fetch('/api/v1/notifications/channels/'+id).then(function(r){return r.json()}).then(function(ch){
    if(ch.error)return;
    editingChannelId=ch.id;
    document.getElementById('notif-add-form').classList.add('visible');
    document.getElementById('notif-error').textContent='';document.getElementById('notif-error').style.display='none';
    document.getElementById('notif-save').textContent='Update Channel';
    document.getElementById('notif-name').value=ch.name||'';
    document.getElementById('notif-enabled').value=ch.enabled?'1':'0';
    var typeSel=document.getElementById('notif-type');typeSel.value=ch.type||'';
    typeSel.dispatchEvent(new Event('change'));
    setTimeout(function(){
      var cfg=ch.config||{};
      var minSev=cfg.min_severity||ch.min_severity||'warning';
      document.getElementById('notif-severity').value=minSev;
      var fields=document.querySelectorAll('#notif-type-fields [data-field]');
      for(var i=0;i<fields.length;i++){
        var key=fields[i].getAttribute('data-field');
        if(cfg[key]!=null){
          if(Array.isArray(cfg[key]))fields[i].value=cfg[key].join(', ');
          else if(typeof cfg[key]==='boolean')fields[i].value=String(cfg[key]);
          else if(typeof cfg[key]==='object')fields[i].value=JSON.stringify(cfg[key]);
          else fields[i].value=String(cfg[key]);
        }
      }
    },50);
  }).catch(function(){});
}
function _toggleChannel(id,enabled){
  fetch('/api/v1/notifications/channels/'+id,{method:'PUT',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({enabled:enabled})}).then(function(){loadNotifications();}).catch(function(){});
}
function _deleteChannel(id){
  fetch('/api/v1/notifications/channels/'+id,{method:'DELETE',headers:csrfHeaders()}).then(function(){loadNotifications();}).catch(function(){});
}
document.getElementById('notif-add-btn').addEventListener('click',function(){
  if(this.classList.contains('disabled')){_showUpgradePrompt();return;}
  editingChannelId=null;
  var form=document.getElementById('notif-add-form');form.classList.toggle('visible');
  document.getElementById('notif-error').textContent='';document.getElementById('notif-error').style.display='none';
  document.getElementById('notif-name').value='';
  document.getElementById('notif-type').value='';
  document.getElementById('notif-type-fields').replaceChildren();
  document.getElementById('notif-severity').value='warning';
  document.getElementById('notif-enabled').value='1';
  document.getElementById('notif-save').textContent='Save Channel';
});
document.getElementById('notif-cancel').addEventListener('click',function(){
  editingChannelId=null;document.getElementById('notif-save').textContent='Save Channel';
  document.getElementById('notif-add-form').classList.remove('visible');
});
var _apiChannelIds=[];
function _bulkAction(action){
  if(!_apiChannelIds.length)return;
  var msg=action==='delete'?'Delete all '+_apiChannelIds.length+' channels?':
    (action==='enable'?'Enable':'Disable')+' all '+_apiChannelIds.length+' channels?';
  if(!confirm(msg))return;
  fetch('/api/v1/notifications/channels/batch',{method:'POST',headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify({action:action,ids:_apiChannelIds})}).then(function(){loadNotifications();}).catch(function(){});
}
document.getElementById('notif-enable-all').addEventListener('click',function(){_bulkAction('enable');});
document.getElementById('notif-disable-all').addEventListener('click',function(){_bulkAction('disable');});
document.getElementById('notif-delete-all').addEventListener('click',function(){_bulkAction('delete');});
function _markFieldError(fieldKey,msg){
  var inp=document.querySelector('#notif-type-fields [data-field="'+fieldKey+'"]');
  if(inp){var row=inp.closest('.form-row');
    inp.classList.add('field-error');
    if(row){row.classList.remove('shake');void row.offsetWidth;row.classList.add('shake');}
    inp.focus();
    var em=row&&row.querySelector('.field-error-msg');if(em){em.textContent=msg;em.classList.add('visible');}}
}
function _clearAllFieldErrors(){
  document.querySelectorAll('#notif-type-fields .field-error').forEach(function(el){el.classList.remove('field-error')});
  document.querySelectorAll('#notif-type-fields .shake').forEach(function(el){el.classList.remove('shake')});
  document.querySelectorAll('#notif-type-fields .field-error-msg').forEach(function(el){el.classList.remove('visible');el.textContent=''});
  ['notif-type','notif-name'].forEach(function(id){var el=document.getElementById(id);if(el)el.classList.remove('field-error')});
}
document.getElementById('notif-name').addEventListener('input',function(){this.classList.remove('field-error');
  var ne=document.getElementById('notif-error');ne.textContent='';ne.style.display='none';});
document.getElementById('notif-save').addEventListener('click',function(){
  var errEl=document.getElementById('notif-error');errEl.textContent='';errEl.style.display='none';
  _clearAllFieldErrors();
  var chType=document.getElementById('notif-type').value;
  var name=document.getElementById('notif-name').value.trim();
  var minSev=document.getElementById('notif-severity').value;
  var enabled=document.getElementById('notif-enabled').value==='1';
  if(!chType){var el=document.getElementById('notif-type');el.classList.add('field-error');
    var r=el.closest('.form-row');r.classList.remove('shake');void r.offsetWidth;r.classList.add('shake');
    errEl.textContent='Select a channel type';errEl.style.display='block';el.focus();return;}
  if(!name){var el=document.getElementById('notif-name');el.classList.add('field-error');
    var r=el.closest('.form-row');r.classList.remove('shake');void r.offsetWidth;r.classList.add('shake');
    errEl.textContent='Name is required';errEl.style.display='block';el.focus();return;}
  var config={};var fields=document.querySelectorAll('#notif-type-fields [data-field]');
  for(var i=0;i<fields.length;i++){
    var key=fields[i].getAttribute('data-field');
    var val=fields[i].value;
    if(fields[i].tagName==='SELECT'&&(val==='true'||val==='false'))val=val==='true';
    config[key]=val;}
  if(notifTypes[chType]){
    var typeFields=notifTypes[chType].fields;
    for(var fk in typeFields){if(typeFields.hasOwnProperty(fk)&&typeFields[fk].required&&fk!=='min_severity'){
      if(!config[fk]){_markFieldError(fk,typeFields[fk].label+' is required');
        errEl.textContent=typeFields[fk].label+' is required';errEl.style.display='block';return;}}}}
  if(config.headers&&typeof config.headers==='string'&&config.headers.trim()){
    try{config.headers=JSON.parse(config.headers);}catch(e){_markFieldError('headers','Must be valid JSON');
      errEl.textContent='Invalid JSON in headers';errEl.style.display='block';return;}}
  if(config.to_addrs&&typeof config.to_addrs==='string'){
    config.to_addrs=config.to_addrs.split(',').map(function(a){return a.trim()}).filter(Boolean);}
  if(config.smtp_port)config.smtp_port=Number.parseInt(config.smtp_port)||587;
  var payload={name:name,type:chType,config:config,min_severity:minSev,enabled:enabled};
  var url='/api/v1/notifications/channels';var method='POST';
  if(editingChannelId){url+='/'+editingChannelId;method='PUT';}
  fetch(url,{method:method,headers:csrfHeaders({'Content-Type':'application/json'}),
    body:JSON.stringify(payload)}).then(function(r){return r.json()}).then(function(res){
    if(res.error){errEl.textContent=res.message||res.error;errEl.style.display='block';return;}
    document.getElementById('notif-add-form').classList.remove('visible');
    editingChannelId=null;document.getElementById('notif-save').textContent='Save Channel';
    loadNotifications();
  }).catch(function(e){errEl.textContent='Failed: '+e.message;errEl.style.display='block';});
});
