from pathlib import Path

path = Path("templates/index.html")
html = path.read_text(encoding="utf-8")

old_section = '''    <div class="log-title">Security checks</div>
    <ul id="checks"></ul>
  </section>'''

new_section = '''    <div class="log-title">Security checks</div>
    <ul id="checks"></ul>

    <section id="jarvis-panel" style="margin-top:24px;padding:18px;border:1px solid #334155;border-radius:12px;">
      <div class="log-title">JARVIS Analysis</div>
      <p id="jarvis-status">JARVIS details will appear after analysis.</p>
      <div id="jarvis-metrics" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0;"></div>
      <div class="log-title">Behavioral analysis</div>
      <p id="jarvis-behavior"></p>
      <div class="log-title">Forensic report</div>
      <pre id="jarvis-report" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto;padding:12px;border-radius:8px;"></pre>
    </section>
  </section>'''

if old_section not in html:
    raise SystemExit("STOP: Expected HTML section not found. No changes made.")

html = html.replace(old_section, new_section, 1)

old_score = "Number(data.safety_score ?? data.risk_score ?? 0)"
if old_score not in html:
    raise SystemExit("STOP: Expected score code not found. No changes made.")

html = html.replace(
    old_score,
    "Number(data.risk_score ?? data.safety_score ?? 0)",
    1,
)

old_badge = "badge.className = 'badge ' + verdict;"
if old_badge not in html:
    raise SystemExit("STOP: Expected verdict code not found. No changes made.")

html = html.replace(
    old_badge,
    "badge.className = 'badge ' + verdictClass(verdict);",
    1,
)

anchor = "  // ==========================================================\n  // 10. SHOW RESULTS"
if anchor not in html:
    raise SystemExit("STOP: Results rendering anchor not found. No changes made.")

jarvis_code = '''  // JARVIS analysis details
    const jarvis = data.jarvis || {};
    const preScan = jarvis.pre_scan || {};
    const sandbox = jarvis.sandbox || {};
    const behavior = jarvis.behavior || {};
    const report = jarvis.forensic_report || {};

    const status = document.getElementById('jarvis-status');
    const metrics = document.getElementById('jarvis-metrics');
    const behaviorElement = document.getElementById('jarvis-behavior');
    const reportElement = document.getElementById('jarvis-report');

    status.textContent = jarvis.sandbox_triggered === true
      ? 'Sandbox triggered'
      : 'Sandbox not triggered';

    metrics.innerHTML = '';
    [
      ['Pre-scan risk', preScan.risk_score],
      ['Sandbox threat score', sandbox.cumulative_threat_score],
      ['Redirects', sandbox.redirect_count],
      ['Browser events', sandbox.total_browser_events],
      ['Network events', sandbox.total_network_events],
      ['Early termination', sandbox.terminated_early == null ? 'N/A' : (sandbox.terminated_early ? 'Yes' : 'No')],
      ['Behavior score', behavior.behavior_score == null ? 'N/A' : behavior.behavior_score + '/100'],
      ['Behavior verdict', behavior.verdict || 'N/A']
    ].forEach(function (item) {
      const card = document.createElement('div');
      card.style.cssText = 'padding:10px;border:1px solid #334155;border-radius:8px;min-width:0;';
      const label = document.createElement('div');
      label.style.cssText = 'font-size:12px;opacity:.75;margin-bottom:5px;';
      label.textContent = item[0];
      const value = document.createElement('div');
      value.style.cssText = 'font-weight:600;overflow-wrap:anywhere;';
      value.textContent = item[1] == null ? 'N/A' : String(item[1]);
      card.appendChild(label);
      card.appendChild(value);
      metrics.appendChild(card);
    });

    behaviorElement.textContent =
      behavior.summary || behavior.llm_summary || 'No behavioral summary returned.';
    reportElement.textContent =
      report.narrative || 'No forensic report returned by the API.';

'''

html = html.replace(anchor, jarvis_code + anchor, 1)
path.write_text(html, encoding="utf-8")
print("SUCCESS: JARVIS panel added and frontend updated.")