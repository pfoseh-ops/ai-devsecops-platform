import runpy
import shutil
from pathlib import Path


def test_combined_report_keeps_no_go_with_clean_or_incomplete_scans(tmp_path):
    script = tmp_path / "src/app/generate_report.py"
    script.parent.mkdir(parents=True)
    shutil.copyfile(Path("src/app/generate_report.py"), script)
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "sast-report.txt").write_text("No issues identified.", encoding="utf-8")
    runpy.run_path(str(script))
    text = (reports / "devsecops-report.md").read_text(encoding="utf-8")
    assert "Production readiness: NO GO" in text
    assert "Five SQLite/OpenSSL" in text
    assert "No SCA report found" in text
    assert "No major issues" not in text
