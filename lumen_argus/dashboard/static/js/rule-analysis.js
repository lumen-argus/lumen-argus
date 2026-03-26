/* rule-analysis.js — Rule Analysis page (community).
   Crossfire-powered overlap detection: duplicates, subsets, overlaps.
   When crossfire not installed, shows install instructions.

   Security: all user-derived content escaped via _esc() (textContent-based).
   innerHTML used only with escaped content — same pattern as rules.js. */

var _raHtml = ''
  + '<div class="sh"><h2>Rule Analysis</h2>'
  + '<div class="btn btn-sm btn-primary" id="ra-analyze-btn">Analyze</div></div>'
  + '<div id="ra-status"></div>'
  + '<div id="ra-content"></div>';

registerPage('rule-analysis', 'Rule Analysis', {order: 35, loadFn: loadRuleAnalysis, html: _raHtml});

var _raEventsWired = false;
function _wireRaEvents() {
  if (_raEventsWired) return;
  _raEventsWired = true;
  var btn = document.getElementById('ra-analyze-btn');
  if (btn) btn.addEventListener('click', _triggerAnalysis);
}

function loadRuleAnalysis() {
  _wireRaEvents();
  // Check if analysis is currently running
  fetch('/api/v1/rules/analysis/status').then(function(r) { return r.json(); }).then(function(s) {
    if (s.running) {
      var btn = document.getElementById('ra-analyze-btn');
      if (btn) { btn.textContent = 'Analyzing...'; btn.classList.add('disabled'); }
      _raShowProgress(s.progress || 'Analysis in progress...');
      _raStartPolling();
      return;
    }
    // Not running — load results
    fetch('/api/v1/rules/analysis').then(function(r) { return r.json(); }).then(function(data) {
      _renderRaPage(data);
    }).catch(function(e) {
      showPageError('ra-content', 'Failed to load analysis: ' + e.message, loadRuleAnalysis);
    });
  }).catch(function() {
    // Status endpoint failed — fall back to loading results directly
    fetch('/api/v1/rules/analysis').then(function(r) { return r.json(); }).then(function(data) {
      _renderRaPage(data);
    }).catch(function(e) {
      showPageError('ra-content', 'Failed to load analysis: ' + e.message, loadRuleAnalysis);
    });
  });
}

function _renderRaPage(data) {
  var statusEl = document.getElementById('ra-status');
  var contentEl = document.getElementById('ra-content');
  var btn = document.getElementById('ra-analyze-btn');
  if (!statusEl || !contentEl) return;

  // Not available — crossfire not installed
  if (data.available === false) {
    if (btn) btn.style.display = 'none';
    statusEl.textContent = '';
    contentEl.textContent = '';
    var unavail = document.createElement('div');
    unavail.className = 'ra-unavailable';
    var h3 = document.createElement('h3');
    h3.textContent = 'Rule overlap analysis requires Crossfire';
    unavail.appendChild(h3);
    var p = document.createElement('p');
    p.textContent = 'Crossfire detects duplicate, subset, and overlapping rules so you can disable redundant ones.';
    unavail.appendChild(p);
    var cmds = document.createElement('div');
    cmds.className = 'ra-install-cmds';
    var c1 = document.createElement('code');
    c1.textContent = 'pip install crossfire';
    cmds.appendChild(c1);
    var sep = document.createElement('span');
    sep.className = 'ra-install-or';
    sep.textContent = ' or ';
    cmds.appendChild(sep);
    var c2 = document.createElement('code');
    c2.textContent = 'pip install lumen-argus[rules-analysis]';
    cmds.appendChild(c2);
    unavail.appendChild(cmds);
    contentEl.appendChild(unavail);
    return;
  }

  if (btn) btn.style.display = '';

  // No results yet
  if (!data.has_results) {
    statusEl.textContent = '';
    contentEl.textContent = '';
    var empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No analysis results yet. Click Analyze to detect rule overlaps.';
    contentEl.appendChild(empty);
    return;
  }

  // Render status bar
  var s = data.summary || {};
  _raRenderStatus(statusEl, data, s);

  // Render content sections
  contentEl.textContent = '';
  var hasContent = false;

  if ((data.duplicates || []).length > 0) {
    contentEl.appendChild(_raSection('Duplicates', data.duplicates, 'dup'));
    hasContent = true;
  }
  if ((data.subsets || []).length > 0) {
    contentEl.appendChild(_raSection('Subsets', data.subsets, 'sub'));
    hasContent = true;
  }
  if ((data.overlaps || []).length > 0) {
    contentEl.appendChild(_raSection('Overlaps', data.overlaps, 'ovr'));
    hasContent = true;
  }

  if ((data.clusters || []).length > 0) {
    contentEl.appendChild(_raClustersSection(data.clusters));
    hasContent = true;
  }

  if (!hasContent) {
    var clean = document.createElement('div');
    clean.className = 'empty';
    clean.textContent = 'No overlaps detected. Your ruleset is clean.';
    contentEl.appendChild(clean);
  }
}

function _raRenderStatus(el, data, s) {
  el.textContent = '';
  var bar = document.createElement('div');
  bar.className = 'ra-status';

  var dot = document.createElement('span');
  dot.className = 'ra-status-dot ra-status-dot--active';
  bar.appendChild(dot);

  var ts = document.createElement('span');
  ts.textContent = 'Last analysis: ' + _raFormatTime(data.timestamp) + ' (' + (data.duration_s || 0) + 's)';
  bar.appendChild(ts);

  _raAppendSep(bar);
  var rules = document.createElement('span');
  rules.textContent = (data.total_rules || 0) + ' rules';
  bar.appendChild(rules);

  _raAppendSep(bar);
  var dups = document.createElement('span');
  dups.className = 'ra-badge-dup';
  dups.textContent = (s.duplicates || 0) + ' duplicates';
  bar.appendChild(dups);

  var subs = document.createElement('span');
  subs.className = 'ra-badge-sub';
  subs.textContent = (s.subsets || 0) + ' subsets';
  bar.appendChild(subs);

  var ovrs = document.createElement('span');
  ovrs.className = 'ra-badge-ovr';
  ovrs.textContent = (s.overlaps || 0) + ' overlaps';
  bar.appendChild(ovrs);

  el.appendChild(bar);
}

function _raAppendSep(parent) {
  var sep = document.createElement('span');
  sep.className = 'ra-status-sep';
  sep.textContent = '\u2022';
  parent.appendChild(sep);
}

function _raSection(title, items, type) {
  var section = document.createElement('div');
  section.className = 'ra-section';
  var h3 = document.createElement('h3');
  h3.textContent = title + ' (' + items.length + ')';
  section.appendChild(h3);
  for (var i = 0; i < items.length; i++) {
    section.appendChild(_raCard(items[i], type));
  }
  return section;
}

function _raCard(item, type) {
  var card = document.createElement('div');
  card.className = 'ra-card ra-card--' + type;
  card.setAttribute('data-rule-a', item.rule_a);
  card.setAttribute('data-rule-b', item.rule_b);

  // Header: rule names + metric
  var header = document.createElement('div');
  header.className = 'ra-card-header';
  var rulesSpan = document.createElement('span');
  rulesSpan.className = 'ra-card-rules';
  var bA = document.createElement('b');
  bA.textContent = item.rule_a;
  rulesSpan.appendChild(bA);
  var relText = type === 'sub' ? ' is subset of ' : ' \u2194 ';
  rulesSpan.appendChild(document.createTextNode(relText));
  var bB = document.createElement('b');
  bB.textContent = item.rule_b;
  rulesSpan.appendChild(bB);
  header.appendChild(rulesSpan);

  var metric = document.createElement('span');
  metric.className = 'ra-card-metric';
  metric.textContent = type === 'ovr'
    ? 'A\u2192B: ' + _raPct(item.overlap_a_to_b) + '  B\u2192A: ' + _raPct(item.overlap_b_to_a)
    : 'Jaccard: ' + _raPct(item.jaccard);
  header.appendChild(metric);
  card.appendChild(header);

  // Meta: tier badges + reason
  var meta = document.createElement('div');
  meta.className = 'ra-card-meta';
  if (item.tier_a) {
    var tA = document.createElement('span');
    tA.className = 'ra-badge-tier';
    tA.textContent = item.tier_a;
    meta.appendChild(tA);
  }
  if (item.tier_b) {
    var tB = document.createElement('span');
    tB.className = 'ra-badge-tier';
    tB.textContent = item.tier_b;
    meta.appendChild(tB);
  }
  if (item.reason) {
    var reason = document.createElement('span');
    reason.className = 'ra-card-reason';
    reason.textContent = item.reason;
    meta.appendChild(reason);
  }
  card.appendChild(meta);

  // Actions: Disable, Review, Dismiss
  var actions = document.createElement('div');
  actions.className = 'ra-card-actions';

  var rec = item.recommendation || '';
  var disableTarget = '';
  if (rec === 'keep_a' || rec === 'KEEP_A') disableTarget = item.rule_b;
  else if (rec === 'keep_b' || rec === 'KEEP_B') disableTarget = item.rule_a;

  if (disableTarget) {
    var disBtn = document.createElement('div');
    disBtn.className = 'btn btn-sm btn-danger ra-disable-btn';
    disBtn.setAttribute('data-rule', disableTarget);
    disBtn.textContent = 'Disable ' + disableTarget;
    disBtn.addEventListener('click', _raDisableHandler);
    actions.appendChild(disBtn);
  }

  var revBtn = document.createElement('div');
  revBtn.className = 'btn btn-sm ra-review-btn';
  revBtn.textContent = 'Review';
  revBtn.addEventListener('click', function() {
    window.location.hash = '#rules?q=' + encodeURIComponent(item.rule_a + ',' + item.rule_b);
  });
  actions.appendChild(revBtn);

  var dismissBtn = document.createElement('div');
  dismissBtn.className = 'btn btn-sm ra-dismiss-btn';
  dismissBtn.textContent = '\u00d7';
  dismissBtn.addEventListener('click', function() {
    fetch('/api/v1/rules/analysis/dismiss', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({rule_a: item.rule_a, rule_b: item.rule_b})
    }).then(function() { card.remove(); });
  });
  actions.appendChild(dismissBtn);

  card.appendChild(actions);
  return card;
}

function _raDisableHandler() {
  var btn = this;
  var ruleName = btn.getAttribute('data-rule');
  if (!ruleName) return;
  btn.textContent = 'Disabling...';
  btn.classList.add('disabled');
  fetch('/api/v1/rules/' + encodeURIComponent(ruleName), {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled: false})
  }).then(function(r) { return r.json(); }).then(function() {
    var card = btn.closest('.ra-card');
    if (card) card.classList.add('ra-card--resolved');
    btn.textContent = 'Disabled';
  }).catch(function() {
    btn.textContent = 'Failed';
    btn.classList.remove('disabled');
  });
}

function _raClustersSection(clusters) {
  var section = document.createElement('div');
  section.className = 'ra-section';
  var h3 = document.createElement('h3');
  h3.textContent = 'Clusters (' + clusters.length + ')';
  section.appendChild(h3);
  for (var i = 0; i < clusters.length; i++) {
    var c = clusters[i];
    var div = document.createElement('div');
    div.className = 'ra-cluster';
    var rSpan = document.createElement('span');
    rSpan.className = 'ra-cluster-rules';
    rSpan.textContent = (c.rules || []).join(', ');
    div.appendChild(rSpan);
    if (c.keep) {
      var kSpan = document.createElement('span');
      kSpan.className = 'ra-cluster-keep';
      kSpan.textContent = 'Keep: ' + c.keep;
      div.appendChild(kSpan);
    }
    section.appendChild(div);
  }
  return section;
}

var _raPollingTimer = null;

function _triggerAnalysis() {
  var btn = document.getElementById('ra-analyze-btn');
  if (!btn || btn.classList.contains('disabled')) return;
  btn.textContent = 'Analyzing...';
  btn.classList.add('disabled');

  _raShowProgress('Starting analysis...');

  fetch('/api/v1/rules/analysis', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'}
  }).then(function(r) { return r.json(); }).then(function(data) {
    if (data.error) {
      btn.textContent = 'Analyze';
      btn.classList.remove('disabled');
      _raShowProgress(data.message || data.error);
      return;
    }
    _raStartPolling();
  }).catch(function() {
    btn.textContent = 'Analyze';
    btn.classList.remove('disabled');
  });
}

function _raShowProgress(text) {
  var contentEl = document.getElementById('ra-content');
  if (!contentEl) return;
  contentEl.textContent = '';

  var bar = document.createElement('div');
  bar.className = 'ra-progress';
  bar.id = 'ra-progress-bar';
  var spinner = document.createElement('div');
  spinner.className = 'ra-progress-spinner';
  bar.appendChild(spinner);
  var msg = document.createElement('span');
  msg.className = 'ra-progress-text';
  msg.id = 'ra-progress-text';
  msg.textContent = text;
  bar.appendChild(msg);

  contentEl.appendChild(bar);

  var terminal = document.createElement('div');
  terminal.className = 'ra-terminal';
  terminal.id = 'ra-terminal';
  contentEl.appendChild(terminal);
}

var _raLogCursor = 0;

function _raStartPolling() {
  _raLogCursor = 0;
  if (_raPollingTimer) clearInterval(_raPollingTimer);
  _raPollingTimer = setInterval(function() {
    fetch('/api/v1/rules/analysis/status?since=' + _raLogCursor)
      .then(function(r) { return r.json(); })
      .then(function(s) {
        var textEl = document.getElementById('ra-progress-text');
        if (textEl && s.progress) textEl.textContent = s.progress;

        var terminal = document.getElementById('ra-terminal');
        if (terminal && s.log && s.log.length > 0) {
          for (var i = 0; i < s.log.length; i++) {
            var line = document.createElement('div');
            line.className = 'ra-terminal-line';
            line.textContent = s.log[i];
            terminal.appendChild(line);
          }
          _raLogCursor = s.log_offset;
          terminal.scrollTop = terminal.scrollHeight;
        }

        if (!s.running) {
          _raStopPolling();
          loadRuleAnalysis();
        }
      }).catch(function() { _raStopPolling(); });
  }, 250);
}

function _raStopPolling() {
  if (_raPollingTimer) { clearInterval(_raPollingTimer); _raPollingTimer = null; }
  var btn = document.getElementById('ra-analyze-btn');
  if (btn) { btn.textContent = 'Analyze'; btn.classList.remove('disabled'); }
}

function _raPct(val) {
  if (val == null) return '\u2014';
  return (val * 100).toFixed(0) + '%';
}

function _raFormatTime(ts) {
  if (!ts) return '\u2014';
  try {
    var d = new Date(ts);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  } catch(e) { return ts; }
}

// Listen for SSE analysis completion
if (typeof window !== 'undefined') {
  document.addEventListener('rule_analysis_complete', function() {
    var page = document.getElementById('page-rule-analysis');
    if (page && page.style.display !== 'none') loadRuleAnalysis();
  });
}
