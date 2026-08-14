<h1 align="center">🔐 Phishing Detection & Awareness System</h1>

<p align="center">
  A Python CLI tool that analyzes URLs for common phishing indicators and generates a weighted risk score from <b>0–100</b>.
</p>

<hr>

<h2>🚀 Features</h2>

<ul>
  <li>🔎 URL and domain structure analysis</li>
  <li>🌐 SSL/TLS certificate checks</li>
  <li>🔀 Redirect chain analysis</li>
  <li>🎯 Brand impersonation detection</li>
  <li>⚠️ Suspicious keyword and TLD detection</li>
  <li>📊 Risk scoring from 0–100</li>
  <li>🗄️ SQLite analysis history</li>
  <li>📤 CSV report export</li>
  <li>📡 Offline analysis mode</li>
  <li>📋 JSON output for automation</li>
</ul>

<h2>📊 Risk Levels</h2>

<table>
  <tr>
    <th>Score</th>
    <th>Risk Level</th>
  </tr>
  <tr>
    <td>0–14</td>
    <td>🟢 Low</td>
  </tr>
  <tr>
    <td>15–34</td>
    <td>🟡 Medium</td>
  </tr>
  <tr>
    <td>35–64</td>
    <td>🟠 High</td>
  </tr>
  <tr>
    <td>65–100</td>
    <td>🔴 Critical</td>
  </tr>
</table>

<h2>⚙️ Installation</h2>

<pre>
pip install -r requirements.txt
</pre>

<p>Requires Python 3.9+.</p>

<h2>💻 Usage</h2>

<p><b>Analyze a URL:</b></p>

<pre>
python main.py check "http://paypal-secure.verify-login.xyz/webscr@confirm"
</pre>

<p><b>Offline analysis:</b></p>

<pre>
python main.py check "http://192.168.1.5/login" --offline
</pre>

<p><b>JSON output:</b></p>

<pre>
python main.py check "https://example.com" --json
</pre>

<p><b>View history:</b></p>

<pre>
python main.py history --limit 10
</pre>

<p><b>Export history:</b></p>

<pre>
python main.py export report.csv
</pre>

<h2>📁 Project Structure</h2>

<pre>
phishing_detector/
├── main.py
├── analyzer.py
├── structural_checks.py
├── network_checks.py
├── scoring.py
├── report.py
├── history.py
├── models.py
├── url_utils.py
└── requirements.txt
</pre>

<h2>🛠️ Built With</h2>

<p>
🐍 Python &nbsp; | &nbsp;
🔐 Cybersecurity &nbsp; | &nbsp;
🗄️ SQLite &nbsp; | &nbsp;
🌐 SSL/TLS &nbsp; | &nbsp;
📊 JSON/CSV
</p>

<h2>🔮 Future Improvements</h2>

<ul>
  <li>Live threat-intelligence integration</li>
  <li>WHOIS/domain-age analysis</li>
  <li>Machine-learning based detection</li>
  <li>Flask/FastAPI web interface</li>
  <li>SIEM/SOAR integration</li>
</ul>

<h2>⚠️ Disclaimer</h2>

<p>
This is a <b>heuristic awareness and educational tool</b>, not a guarantee of safety.
A low-risk result does not mean a URL is automatically safe.
Always verify suspicious links through trusted sources.
</p>

<h2>👨‍💻 Author</h2>

<p>
<b>Toluwalase Odunuyi</b><br>
</p>
