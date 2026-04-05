from jinja2 import Template
import json

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>数据库漏洞扫描报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Microsoft YaHei', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 5px solid #3498db;
        }

        .summary-card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }

        .summary-card .number {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }

        .vulnerabilities {
            padding: 30px;
        }

        .vulnerability-card {
            background: white;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .vulnerability-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.15);
        }

        .vulnerability-header {
            padding: 20px 30px;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }

        .vulnerability-header.critical {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }

        .vulnerability-header.high {
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
        }

        .vulnerability-header.medium {
            background: linear-gradient(135deg, #f1c40f 0%, #f39c12 100%);
        }

        .vulnerability-header.low {
            background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
        }

        .vulnerability-header h3 {
            color: white;
            font-size: 1.4em;
            margin-bottom: 5px;
        }

        .vulnerability-header p {
            color: rgba(255,255,255,0.9);
            font-size: 0.9em;
        }

        .vulnerability-content {
            padding: 30px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .info-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #3498db;
        }

        .info-section h4 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }

        .info-section p {
            margin-bottom: 10px;
            line-height: 1.5;
        }

        .cve-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin: 20px 0;
        }

        .cve-section h4 {
            color: white;
            margin-bottom: 15px;
            font-size: 1.2em;
        }

        .cve-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }

        .cve-card {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }

        .cve-card h5 {
            color: #ffd700;
            margin-bottom: 8px;
            font-size: 1em;
        }

        .cve-card p {
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .cve-card .cve-year {
            color: #87ceeb;
            font-weight: bold;
        }

        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-family: 'Consolas', 'Monaco', monospace;
            overflow-x: auto;
            white-space: pre-wrap;
        }

        .references {
            margin-top: 20px;
        }

        .references h4 {
            color: #2c3e50;
            margin-bottom: 10px;
        }

        .references ul {
            list-style: none;
            padding: 0;
        }

        .references li {
            margin-bottom: 5px;
        }

        .references a {
            color: #3498db;
            text-decoration: none;
        }

        .references a:hover {
            text-decoration: underline;
        }

        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 2em;
            }

            .summary {
                grid-template-columns: 1fr;
            }

            .info-grid {
                grid-template-columns: 1fr;
            }

            .cve-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ 数据库漏洞扫描报告</h1>
            <p>扫描完成时间: {{ timestamp }}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>扫描目标总数</h3>
                <div class="number">{{ total_targets }}</div>
            </div>
            <div class="summary-card">
                <h3>发现漏洞数量</h3>
                <div class="number">{{ len(vulnerabilities) }}</div>
            </div>
            <div class="summary-card">
                <h3>高危漏洞</h3>
                <div class="number">{{ vulnerabilities | selectattr('severity', 'equalto', 'CRITICAL') | list | length + vulnerabilities | selectattr('severity', 'equalto', 'HIGH') | list | length }}</div>
            </div>
            <div class="summary-card">
                <h3>中低危漏洞</h3>
                <div class="number">{{ vulnerabilities | selectattr('severity', 'equalto', 'MEDIUM') | list | length + vulnerabilities | selectattr('severity', 'equalto', 'LOW') | list | length }}</div>
            </div>
        </div>

        <div class="vulnerabilities">
            <h2 style="text-align: center; margin-bottom: 30px; color: #2c3e50;">🔍 详细漏洞信息</h2>

            {% for vuln in vulnerabilities %}
            <div class="vulnerability-card">
                <div class="vulnerability-header {{ vuln.severity.lower() }}">
                    <h3>{{ vuln.vulnerability_type }}</h3>
                    <p>{{ vuln.target.host }}:{{ vuln.target.port }} - {{ vuln.severity }}</p>
                </div>

                <div class="vulnerability-content">
                    <div class="info-grid">
                        <div class="info-section">
                            <h4>📋 漏洞描述</h4>
                            <p>{{ vuln.description }}</p>
                        </div>

                        <div class="info-section">
                            <h4>🎯 利用方式</h4>
                            <p>{{ vuln.exploitation }}</p>
                        </div>

                        <div class="info-section">
                            <h4>🔧 修复方案</h4>
                            <p>{{ vuln.remediation | replace('\\n', '<br>') | safe }}</p>
                        </div>

                        <div class="info-section">
                            <h4>📊 检测证据</h4>
                            <p>{{ vuln.evidence }}</p>
                        </div>
                    </div>

                    {% if vuln.cve_info %}
                    <div class="cve-section">
                        <h4>🚨 相关CVE漏洞信息</h4>
                        <div class="cve-grid">
                            {% for cve in vuln.cve_info %}
                            <div class="cve-card">
                                <h5>{{ cve.cve }}</h5>
                                <p><strong>严重程度:</strong> {{ cve.severity }}</p>
                                <p><strong>发现时间:</strong> {{ cve.discovery_date }}</p>
                                <p><strong>受影响版本:</strong> {{ cve.affected_versions }}</p>
                                <p><span class="cve-year">{{ cve.year }}年</span></p>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}

                    <div class="info-section">
                        <h4>💻 POC演示</h4>
                        <div class="code-block">{{ vuln.poc }}</div>
                    </div>

                    {% if vuln.cve_info %}
                    {% for cve in vuln.cve_info %}
                    <div class="info-section">
                        <h4>🔍 {{ cve.cve }} 测试方法</h4>
                        <p>{{ cve.test_method | replace('\\n', '<br>') | safe }}</p>
                    </div>

                    <div class="info-section">
                        <h4>🛠️ {{ cve.cve }} 完整修复方案</h4>
                        <p>{{ cve.fix_method | replace('\\n', '<br>') | safe }}</p>
                    </div>

                    {% if cve.exploit_tools %}
                    <div class="info-section">
                        <h4>⚡ {{ cve.cve }} 利用工具</h4>
                        <ul>
                            {% for tool in cve.exploit_tools %}
                            <li><a href="{{ tool }}" target="_blank">{{ tool }}</a></li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    {% endfor %}
                    {% endif %}

                    <div class="references">
                        <h4>📚 参考资料</h4>
                        <ul>
                            {% for ref in vuln.references %}
                            <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                            {% endfor %}
                        </ul>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            <p>© 2024 数据库安全扫描工具 | 生成时间: {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
"""

def generate_html_report(vulnerabilities, total_targets, timestamp):
    template = Template(HTML_TEMPLATE)
    return template.render(
        vulnerabilities=vulnerabilities,
        total_targets=total_targets,
        timestamp=timestamp
    )

def save_report(report_html, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report_html)