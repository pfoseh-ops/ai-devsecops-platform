"""Guard the dependency and failure-handling contracts of the CI pipeline."""
from pathlib import Path

import yaml


def workflow_jobs():
    return yaml.safe_load(Path('.github/workflows/devsecops.yml').read_text(encoding='utf-8'))['jobs']


def test_build_consumers_are_independent_and_report_waits_for_every_job():
    jobs = workflow_jobs()
    assert set(jobs) == {'tests', 'sast', 'sca', 'build', 'image_security', 'dast', 'report'}
    for name in ('tests', 'sast', 'sca', 'build'):
        assert not jobs[name].get('needs')
    for name in ('image_security', 'dast'):
        assert jobs[name]['needs'] == ['build']
    assert set(jobs['report']['needs']) == set(jobs) - {'report'}
    assert jobs['report']['if'] == '${{ always() }}'


def test_only_one_build_and_both_consumers_use_the_uploaded_image():
    jobs = workflow_jobs()
    builds = [(name, step) for name, job in jobs.items() for step in job['steps']
              if 'docker build ' in step.get('run', '')]
    assert len(builds) == 1
    assert builds[0][0] == 'build'
    for name in ('image_security', 'dast'):
        steps = jobs[name]['steps']
        download = next(step for step in steps if step.get('id') == 'download_image')
        assert download['with']['name'] == 'built-image'
        verify = next(step for step in steps if step.get('id') == 'verify_image')['run']
        assert 'docker image load --input reports/runtime-image.tar' in verify
        assert 'assert actual == expected' in verify
    scan = next(step for step in jobs['image_security']['steps'] if step.get('id') == 'scan')
    assert scan['with']['input'] == 'reports/runtime-image.tar'
    assert scan['with']['exit-code'] == '0'
    assert scan['with']['ignore-unfixed'] == 'false'
    zap = next(step for step in jobs['dast']['steps'] if step.get('id') == 'zap')['run']
    assert 'zap-baseline.py' in zap and ' -I' in zap


def test_failures_remain_failures_but_evidence_uploads_still_run():
    jobs = workflow_jobs()
    for name, job in jobs.items():
        if name == 'report':
            continue
        assert not job.get('continue-on-error')
        for step in job['steps']:
            assert not step.get('continue-on-error')
            if 'actions/upload-artifact@' in step.get('uses', ''):
                if step['with']['name'] != 'built-image':
                    assert step['if'] == 'always()'
    report = jobs['report']['steps']
    downloads = [step for step in report if 'actions/download-artifact@' in step.get('uses', '')]
    assert len(downloads) == 6
    assert all(step['continue-on-error'] for step in downloads)
    assert all(step['with']['name'] != 'built-image' for step in downloads)
    upload = next(step for step in report if 'actions/upload-artifact@' in step.get('uses', ''))
    assert upload['with']['path'] == 'reports/'
    zap_upload = next(step for step in jobs['dast']['steps'] if 'actions/upload-artifact@' in step.get('uses', ''))
    assert 'reports/zap-report.html' in zap_upload['with']['path']
