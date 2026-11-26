import json

from scripts.record_ci_status import main


def test_original_step_failure_is_preserved(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GITHUB_JOB', 'tests')
    steps = {'pytest': {'outcome': 'failure', 'conclusion': 'failure'},
             'lint': {'outcome': 'skipped', 'conclusion': 'skipped'}}
    monkeypatch.setenv('CI_STEPS_JSON', json.dumps(steps))
    main()
    assert json.loads((tmp_path / 'reports/tests-status.json').read_text()) == steps
