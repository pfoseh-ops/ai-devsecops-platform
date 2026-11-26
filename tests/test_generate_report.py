import json
import runpy
import shutil
from pathlib import Path

import pytest


@pytest.fixture
def render(tmp_path, monkeypatch):
    script = tmp_path / 'src/app/generate_report.py'
    script.parent.mkdir(parents=True)
    shutil.copyfile(Path('src/app/generate_report.py'), script)
    reports = tmp_path / 'reports'
    reports.mkdir()
    monkeypatch.delenv('CI_NEEDS_JSON', raising=False)
    monkeypatch.delenv('CI_DOWNLOADS_JSON', raising=False)

    def generate(needs=None, downloads=None, files=None):
        monkeypatch.setenv('CI_NEEDS_JSON', json.dumps(needs or {}))
        monkeypatch.setenv('CI_DOWNLOADS_JSON', json.dumps(downloads or {}))
        for name, value in (files or {}).items():
            (reports / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf-8')
        runpy.run_path(str(script))
        return (reports / 'devsecops-report.md').read_text(encoding='utf-8')

    return generate


def test_failures_and_skips_remain_distinct_from_missing_artifacts(render):
    text = render(
        needs={'tests': {'result': 'failure'}, 'build': {'result': 'failure'},
               'image_security': {'result': 'skipped'}, 'dast': {'result': 'skipped'}},
        downloads={'download_tests': {'outcome': 'failure', 'conclusion': 'success'}},
        files={'tests-status.json': {'pytest': {'outcome': 'failure'}, 'lint': {'outcome': 'skipped'}}},
    )
    assert '| tests | failure | Missing/empty: `test-report.txt` | failure |' in text
    assert '| dast | skipped (build: failure)' in text
    assert '| image_security | skipped (build: failure)' in text
    assert 'tests/pytest: **failure**' in text
    assert 'tests/lint: **skipped**' in text
    assert 'Production readiness: NO GO' in text


def test_successful_scan_with_findings_does_not_become_security_approval(render):
    text = render(
        needs={'sast': {'result': 'success'}, 'dast': {'result': 'success'}},
        files={'sast-report.json': {'results': [{'issue_severity': 'LOW', 'issue_confidence': 'HIGH'}]},
               'zap-report.json': {'site': [{'alerts': [{'riskcode': '2'}]}]},
               'zap-report.html': '<html>ZAP warning</html>'},
    )
    assert '| sast | success | Missing/empty:' in text
    assert 'Bandit findings: 1; HIGH severity/HIGH confidence: 0' in text
    assert 'ZAP alert types across sites: 1' in text
    assert 'Risk 2: 1' in text
    assert '[zap-report.html](zap-report.html)' in text
    assert 'Production readiness: NO GO' in text


def test_malformed_scan_evidence_does_not_prevent_report(render):
    text = render(files={'sast-report.json': '{broken', 'zap-report.json': 'null',
                         'tests-status.json': '[]'})
    assert 'Malformed/unreadable evidence: `sast-report.json`' in text
    assert 'tests: check-level outcomes unavailable' in text
    assert '| tests | unknown |' in text
    assert 'Production readiness: NO GO' in text


@pytest.mark.parametrize('different', [False, True])
def test_image_identity_comparison(render, different):
    identity = {'image_id': 'sha256:built', 'diff_ids': ['layer'], 'os': 'linux', 'architecture': 'amd64'}
    dast = {**identity, 'image_id': 'sha256:other'} if different else identity
    text = render(files={'build-image.json': identity, 'runtime-image.json': identity,
                         'dast-image.json': dast, 'dast-container-image.txt': dast['image_id']})
    assert ('**MISMATCH**' if different else 'identities: MATCH.') in text
    assert 'Running DAST container image:' in text


def test_cancelled_job_and_skipped_download_are_visible(render):
    text = render(needs={'sca': {'result': 'cancelled'}},
                  downloads={'download_sca': {'outcome': 'skipped'}})
    assert '| sca | cancelled |' in text
    assert '`sca-status.json` | skipped |' in text


def test_combined_report_keeps_no_go_with_clean_or_incomplete_scans(tmp_path):
    script = tmp_path / "src/app/generate_report.py"
    script.parent.mkdir(parents=True)
    shutil.copyfile(Path("src/app/generate_report.py"), script)
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "sast-report.txt").write_text("No issues identified.", encoding="utf-8")
    (reports / "runtime-image-summary.md").write_text(
        "## Runtime image scan and SBOM\n\nImage evidence: synthetic-config-digest\n", encoding="utf-8"
    )
    runpy.run_path(str(script))
    text = (reports / "devsecops-report.md").read_text(encoding="utf-8")
    assert "Production readiness: NO GO" in text
    assert "Five SQLite/OpenSSL" in text
    assert "No SCA report found" in text
    assert "No major issues" not in text
    assert "Image evidence: synthetic-config-digest" in text
