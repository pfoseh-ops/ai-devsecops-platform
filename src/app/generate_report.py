import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'reports'
REPORTS.mkdir(exist_ok=True)

out = []
out.append('# DevSecOps Consolidated Report\n')


def read_text(path):
    for encoding in ('utf-8-sig', 'utf-16', 'latin-1'):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeError:
            continue


def read_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(read_text(path))
    except (ValueError, OSError):
        out.append(f'- Malformed/unreadable evidence: `{path.name}`.\n')
        return None


def env_json(name):
    try:
        value = json.loads(os.environ.get(name, '{}'))
        if isinstance(value, dict):
            return value
    except ValueError:
        pass
    out.append(f'- Invalid status metadata: `{name}`; outcomes unknown.\n')
    return {}


needs = env_json('CI_NEEDS_JSON')
downloads = env_json('CI_DOWNLOADS_JSON')
# Save the authoritative scheduler results alongside the human-readable report.
(REPORTS / 'job-results.json').write_text(json.dumps(needs, indent=2), encoding='utf-8')
(REPORTS / 'artifact-downloads.json').write_text(json.dumps(downloads, indent=2), encoding='utf-8')
if all(os.environ.get(key) for key in ('GITHUB_SERVER_URL', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID')):
    run_url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    out.append(f'[Workflow logs and artifacts]({run_url})\n')

out.append('## Job outcomes and evidence\n')
out.append('Job success describes execution and policy checks, not absence of findings or production approval. '
           'Missing evidence is never a passing result.\n')
out.append('| Job | Outcome | Evidence | Artifact download |\n|---|---|---|---|')
expected = {
    'tests': ['test-report.txt', 'tests-status.json'],
    'sast': ['sast-report.txt', 'sast-report.json', 'sast-status.json'],
    'sca': ['sca-report.txt', 'sca-status.json'],
    'build': ['build-report.txt', 'build-image.json', 'build-status.json'],
    'image_security': ['runtime-image.json', 'runtime-image-scan.json', 'runtime-image-sbom.cdx.json',
                       'runtime-image-summary.json', 'runtime-image-summary.md', 'runtime-trivy-version.txt',
                       'runtime-trivy-db.json', 'image_security-status.json'],
    'dast': ['zap-report.html', 'zap-report.json', 'zap.md', 'dast-image.json',
             'dast-container-image.txt', 'dast-status.json'],
}
for job, files in expected.items():
    result = needs.get(job, {}).get('result', 'unknown')
    if result == 'skipped' and job in ('image_security', 'dast'):
        result += f" (build: {needs.get('build', {}).get('result', 'unknown')})"
    missing = [name for name in files if not (REPORTS / name).is_file() or not (REPORTS / name).stat().st_size]
    evidence = 'Available' if not missing else 'Missing/empty: ' + ', '.join(f'`{name}`' for name in missing)
    download = downloads.get(f'download_{job}', {}).get('outcome', 'unknown')
    out.append(f'| {job} | {result} | {evidence} | {download} |')

out.append('\n## Individual check outcomes\n')
for job in expected:
    steps = read_json(REPORTS / f'{job}-status.json')
    if not isinstance(steps, dict):
        out.append(f'- {job}: check-level outcomes unavailable.\n')
        continue
    for step, value in steps.items():
        if isinstance(value, dict):
            out.append(f"- {job}/{step}: **{value.get('outcome', 'unknown')}**\n")

out.append('## Image identity\n')
identities = {}
for label, filename in [('Build', 'build-image.json'), ('Image security', 'runtime-image.json'),
                        ('DAST', 'dast-image.json')]:
    identity = read_json(REPORTS / filename)
    if isinstance(identity, dict) and identity.get('image_id'):
        identities[label] = identity
        out.append(f"- {label}: `{identity['image_id']}`\n")
    else:
        out.append(f'- {label}: identity unavailable or malformed.\n')
if len(identities) == 3:
    match = identities['Build'] == identities['Image security'] == identities['DAST']
    out.append('- Built/loaded image identities: ' + ('MATCH.\n' if match else '**MISMATCH**.\n'))
else:
    out.append('- Built/loaded image identity comparison: incomplete evidence.\n')
container_file = REPORTS / 'dast-container-image.txt'
if container_file.exists():
    container_id = read_text(container_file).strip()
    out.append(f'- Running DAST container image: `{container_id}`\n')
    if identities.get('Build', {}).get('image_id') != container_id:
        out.append('- Running container/build comparison: **MISMATCH or missing build identity**.\n')

out.append('## Security findings and scan policy\n')
out.append('Bandit gates HIGH severity with HIGH confidence. Trivy filesystem and image scans are '
           'report-producing; image findings include unfixed vulnerabilities. ZAP baseline retains `-I`: '
           'warnings do not fail the check. Tool failures remain failures.\n')
bandit = read_json(REPORTS / 'sast-report.json')
if isinstance(bandit, dict) and isinstance(bandit.get('results'), list):
    issues = bandit['results']
    gated = sum(isinstance(issue, dict) and issue.get('issue_severity') == 'HIGH'
                and issue.get('issue_confidence') == 'HIGH' for issue in issues)
    out.append(f'- Bandit findings: {len(issues)}; HIGH severity/HIGH confidence: {gated}.\n')
else:
    out.append('- Bandit structured findings unavailable (missing or malformed evidence).\n')
zap = read_json(REPORTS / 'zap-report.json')
if isinstance(zap, dict) and isinstance(zap.get('site'), list):
    alerts = [alert for site in zap['site'] if isinstance(site, dict)
              for alert in site.get('alerts', []) if isinstance(alert, dict)]
    out.append(f'- ZAP alert types across sites: {len(alerts)} (not a pass/fail result).\n')
    for risk in ('0', '1', '2', '3'):
        count = sum(str(alert.get('riskcode')) == risk for alert in alerts)
        out.append(f'  - Risk {risk}: {count}\n')
else:
    out.append('- ZAP structured findings unavailable (missing or malformed evidence).\n')

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
    sca_text = read_text(sca_file)
    out.append('## SCA (Trivy) Summary\n')
    high = sum(1 for line in sca_text.splitlines() if 'CRITICAL' in line or 'HIGH' in line)
    out.append(f'- Lines mentioning HIGH/CRITICAL (not a unique vulnerability count): {high}\n')
    out.append('```\n' + sca_text + '\n```\n')
else:
    out.append('## SCA (Trivy) Summary\nNo SCA report found.\n')

# SAST
sast_file = REPORTS / 'sast-report.txt'
if sast_file.exists():
    sast_text = read_text(sast_file)
    out.append('## SAST (Bandit) Summary\n')
    high = sum(1 for line in sast_text.splitlines() if 'HIGH' in line or 'High' in line)
    out.append(f'- High findings lines: {high}\n')
    out.append('```\n' + sast_text + '\n```\n')
else:
    out.append('## SAST (Bandit) Summary\nNo SAST report found.\n')

# Runtime image evidence
image_summary = REPORTS / 'runtime-image-summary.md'
if image_summary.exists():
    out.append(read_text(image_summary))
else:
    out.append('## Runtime image scan and SBOM\nNo runtime image evidence found.\n')

# DAST
zap_file = REPORTS / 'zap-report.html'
if zap_file.exists():
    out.append('## DAST (OWASP ZAP) Summary\n')
    out.append('- HTML report attached: [zap-report.html](zap-report.html)\n')
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
