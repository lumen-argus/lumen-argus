/* settings.js — config display, license input, log download */
function loadSettings(){
  fetch('/api/v1/config').then(function(r){return r.json()}).then(function(cfg){
    var el=document.getElementById('settings-content');el.replaceChildren();

    /* License key input */
    var licGrp=document.createElement('div');licGrp.className='setting-group';
    var lh=document.createElement('h3');lh.textContent='License';licGrp.appendChild(lh);
    var licRow=document.createElement('div');licRow.className='form-row';
    var licLbl=document.createElement('label');licLbl.textContent='Key';
    var licInput=document.createElement('input');licInput.type='text';licInput.id='license-key-input';
    licInput.placeholder='Enter Pro license key';licInput.style.flex='1';
    var licBtn=document.createElement('div');licBtn.className='btn btn-primary btn-sm';licBtn.textContent='Activate';
    licBtn.addEventListener('click',function(){
      var key=document.getElementById('license-key-input').value.trim();
      if(!key)return;
      fetch('/api/v1/license',{method:'POST',headers:csrfHeaders({'Content-Type':'application/json'}),
        body:JSON.stringify({key:key})}).then(function(r){return r.json()}).then(function(res){
        var msg=document.getElementById('license-result');
        msg.textContent=res.message||res.error||'Done';
        msg.style.color=res.error?'var(--critical)':'var(--accent)';
        msg.style.display='block';
      }).catch(function(e){
        var msg=document.getElementById('license-result');
        msg.textContent='Failed: '+e.message;msg.style.color='var(--critical)';msg.style.display='block';
      });
    });
    licRow.appendChild(licLbl);licRow.appendChild(licInput);licRow.appendChild(licBtn);
    licGrp.appendChild(licRow);
    var licResult=document.createElement('div');licResult.id='license-result';
    licResult.style.cssText='font-family:var(--font-data);font-size:.78rem;margin-top:6px;display:none';
    licGrp.appendChild(licResult);

    var trialRow=document.createElement('div');trialRow.style.marginTop='10px';
    var trialLink=document.createElement('a');trialLink.href='https://lumen-argus.com/trial';
    trialLink.target='_blank';trialLink.className='btn btn-sm';trialLink.textContent='Start Free Trial';
    trialRow.appendChild(trialLink);
    licGrp.appendChild(trialRow);
    el.appendChild(licGrp);

    /* Read-only config sections */
    var community=cfg.community||{};

    if(community.proxy){
      addSG(el,'Proxy',[
        ['Port',community.proxy.port],['Bind',community.proxy.bind],
        ['Timeout',community.proxy.timeout+'s'],['Retries',community.proxy.retries]
      ]);
    }

    addSG(el,'Actions',[
      ['Default',community.default_action||'alert']
    ]);

    if(community.detectors){
      var detRows=[];
      for(var d in community.detectors){if(community.detectors.hasOwnProperty(d)){
        var det=community.detectors[d];
        detRows.push([d,det.enabled?'Enabled ('+det.action+')':'Disabled',det.enabled]);}}
      addSG(el,'Detectors',detRows);
    }

    /* Log file info + download */
    var logGrp=document.createElement('div');logGrp.className='setting-group';
    var logH=document.createElement('h3');logH.textContent='Logs';logGrp.appendChild(logH);
    var dlBtn=document.createElement('button');
    dlBtn.textContent='Download Sanitized Logs';
    dlBtn.style.cssText='font-family:var(--font-data);font-size:.78rem;padding:6px 14px;background:var(--bg-base);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--accent);cursor:pointer';
    dlBtn.addEventListener('click',function(){window.location.href='/api/v1/logs/download'});
    logGrp.appendChild(dlBtn);
    var dlNote=document.createElement('span');dlNote.style.cssText='font-size:.72rem;color:var(--text-muted);margin-left:8px';
    dlNote.textContent='IPs and file paths are sanitized for safe sharing';
    logGrp.appendChild(dlNote);
    el.appendChild(logGrp);

  }).catch(function(e){showPageError('settings-content','Failed to load settings: '+e.message,loadSettings);});}

function addSG(parent,title,rows){var grp=document.createElement('div');grp.className='setting-group';
  var h=document.createElement('h3');h.textContent=title;grp.appendChild(h);
  for(var i=0;i<rows.length;i++){var row=document.createElement('div');row.className='setting-row';
    var key=document.createElement('div');key.className='setting-key';key.textContent=rows[i][0];
    var val=document.createElement('div');val.className='setting-val';val.textContent=String(rows[i][1]);
    if(rows[i].length>2)val.classList.add(rows[i][2]?'enabled':'disabled');
    row.appendChild(key);row.appendChild(val);grp.appendChild(row);}
  parent.appendChild(grp);}
