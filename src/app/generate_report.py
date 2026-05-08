from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'reports'
REPORTS.mkdir(exist_ok=True)

out = []
out.append('# DevSecOps Consolidated Report\n')

# Tests
test_file = REPORTS / 'test-report.txt'
if test_file.exists():
    out.append('## Test Results\n')
    out.append('```\n' + test_file.read_text() + '\n```\n')
else:
    out.append('## Test Results\nNo test report found.\n')

# SCA
sca_file = REPORTS / 'sca-report.txt'
if sca_file.exists():
    sca_text = sca_file.read_text()
    out.append('## SCA (Trivy) Summary\n')
    high = sum(1 for l in sca_text.splitlines() if 'CRITICAL' in l or 'HIGH' in l)
    out.append(f'- High/Critical findings: {high}\n')
    out.append('```\n' + sca_text + '\n```\n')
else:
    out.append('## SCA (Trivy) Summary\nNo SCA report found.\n')

# SAST
sast_file = REPORTS / 'sast-report.txt'
if sast_file.exists():
    sast_text = sast_file.read_text()
    out.append('## SAST (Bandit) Summary\n')
    high = sum(1 for l in sast_text.splitlines() if 'HIGH' in l or 'High' in l)
    out.append(f'- High findings lines: {high}\n')
    out.append('```\n' + sast_text + '\n```\n')
else:
    out.append('## SAST (Bandit) Summary\nNo SAST report found.\n')

# DAST
zap_file = REPORTS / 'zap-report.html'
if zap_file.exists():
    out.append('## DAST (OWASP ZAP) Summary\n')
    out.append('- HTML report attached: zap-report.html\n')
else:
    out.append('## DAST (OWASP ZAP) Summary\nNo ZAP report found.\n')

# Final risk summary (very basic)
out.append('## Final Risk Summary\n')
risks = 0
if sca_file.exists():
    risks += high
if sast_file.exists():
    risks += sum(1 for l in sast_text.splitlines() if 'HIGH' in l or 'High' in l)
if risks == 0:
    out.append('No major issues detected by automated scanners. Manual review recommended.\n')
else:
    out.append(f'Automated scanners reported {risks} potential high-risk findings. Prioritize remediation.\n')

dev_file = REPORTS / 'devsecops-report.md'
with open(dev_file, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))
print('Generated', dev_file)
