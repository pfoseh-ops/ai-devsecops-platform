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
    try:
        text = test_file.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        try:
            text = test_file.read_text(encoding='utf-16')
        except UnicodeDecodeError:
            text = test_file.read_bytes().decode('latin-1', errors='replace')
    out.append('```\n' + text + '\n```\n')
else:
    out.append('## Test Results\nNo test report found.\n')

# SCA
sca_file = REPORTS / 'sca-report.txt'
if sca_file.exists():
    sca_text = sca_file.read_text()
    out.append('## SCA (Trivy) Summary\n')
    high = sum(1 for line in sca_text.splitlines() if 'CRITICAL' in line or 'HIGH' in line)
    out.append(f'- Lines mentioning HIGH/CRITICAL (not a unique vulnerability count): {high}\n')
    out.append('```\n' + sca_text + '\n```\n')
else:
    out.append('## SCA (Trivy) Summary\nNo SCA report found.\n')

# SAST
sast_file = REPORTS / 'sast-report.txt'
if sast_file.exists():
    sast_text = sast_file.read_text()
    out.append('## SAST (Bandit) Summary\n')
    high = sum(1 for line in sast_text.splitlines() if 'HIGH' in line or 'High' in line)
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

# Report completion is not release approval. Text matches are not CVE counts.
out.append('## Final Risk Summary\n')
out.append(
    '**Production readiness: NO GO.** Scanner text summaries are not release approval. '
    'Five SQLite/OpenSSL CVE dispositions and deployment controls remain unverified. '
    'Review docs/sqlite-openssl-dispositions.md and docs/production-readiness.md.\n'
)

dev_file = REPORTS / 'devsecops-report.md'
with open(dev_file, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))
print('Generated', dev_file)
