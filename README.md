# DBScan - 数据库漏洞扫描工具

一个多线程的Python数据库漏洞扫描脚本，支持多种数据库类型的安全漏洞检测。

## ✨ 主要特性

- 🚀 **多线程扫描**：支持并发扫描多个目标，提高检测效率
- 🎯 **多种数据库支持**：Redis、MySQL、PostgreSQL、MongoDB、Elasticsearch
- 🔍 **深度漏洞检测**：
  - Redis未授权访问及多种RCE漏洞
  - MySQL/PostgreSQL空密码漏洞
  - MongoDB未授权访问
  - Elasticsearch未授权访问
- 📊 **美观HTML报告**：现代化的中文界面，包含详细的漏洞信息
- 📋 **完整测试记录**：记录所有测试包和响应，便于验证

## 🛠️ 安装使用

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 准备目标文件
创建包含数据库URL的文件，每行一个：
```
redis://node.hackhub.get-shell.com:44671
mysql://user:pass@host:port/db
postgresql://user:pass@host:port/db
mongodb://host:port/db
```

### 3. 运行扫描
```bash
python db_scanner.py -i targets.txt -o report.html -t 10
```

### 4. 查看报告
打开生成的`report.html`文件，查看美观的中文扫描报告。

## 📋 命令参数

- `-i, --input`：目标文件路径（必需）
- `-o, --output`：输出报告文件（默认：scan_report.html）
- `-t, --threads`：扫描线程数（默认：10）

## 🔍 支持的漏洞类型

### Redis 漏洞
- **Redis未授权访问**：检测无认证连接（低危）
- **Redis 4.x 远程代码执行**：通过文件写能力实现RCE（严重）
- **Redis恶意模块RCE**：通过加载恶意模块执行代码（高危）
- **Redis从节点配置问题**：从节点配置不当（低危）

### 其他数据库
- **MySQL空密码漏洞**：检测空密码账户（高危）
- **MySQL Root空密码漏洞**：Root用户空密码（严重）
- **PostgreSQL空密码漏洞**：检测空密码账户（严重）
- **MongoDB未授权访问**：检测无认证访问（高危）
- **Elasticsearch未授权访问**：检测无认证访问（中危）

## 📊 报告特性

- 🎨 **现代化界面**：渐变背景，卡片式布局
- 🇨🇳 **全中文显示**：漏洞名称、描述、修复建议全部中文
- 📈 **统计面板**：显示扫描目标数、漏洞数、时间等
- 🏷️ **严重性标识**：不同颜色区分漏洞等级
- 🔗 **参考链接**：提供相关安全资料链接
- 💻 **POC代码**：包含可执行的验证代码

## ⚠️ 注意事项

- 请在获得授权的情况下进行扫描
- 扫描过程中会尝试连接目标服务
- 某些测试可能对目标系统产生影响，请谨慎使用

## 📝 示例输出

```
Starting database vulnerability scan...
Input file: targets.txt
Max workers: 10
2026-04-05 21:25:45 - INFO - Found vulnerability: Redis Unauthenticated Access
2026-04-05 21:25:46 - INFO - Found vulnerability: Redis 4.x Remote Code Execution
Found 3 vulnerabilities!
HTML报告已生成: beautiful_report.html
```

The scanner generates an HTML report containing:
- Vulnerability type and severity
- Detailed description
- Exploitation method
- Proof of concept commands
- Evidence of the vulnerability
- Remediation steps
- Relevant references

## Example

```bash
# Scan with 20 threads
python db_scanner.py -i targets.txt -o my_report.html -t 20

# Basic scan with defaults
python db_scanner.py -i targets.txt
```

## Security Notice

This tool is intended for authorized security testing only. Always ensure you have permission to scan the target systems.