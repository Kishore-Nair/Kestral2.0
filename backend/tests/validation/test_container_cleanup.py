import subprocess
from unittest.mock import patch

from app.validation.sandbox import TestPlan, run_tests_in_container


def test_timeout_removes_only_named_test_container(tmp_path):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, 0, "", "")

    with (
        patch("app.validation.sandbox.shutil.which", return_value="docker"),
        patch("app.validation.sandbox.subprocess.run", side_effect=run),
    ):
        result = run_tests_in_container(
            "docker", TestPlan("node:22-slim", "true", "test"), tmp_path, 1
        )
    name = calls[0][calls[0].index("--name") + 1]
    assert name.startswith("kestral-test-")
    assert calls[1] == ["docker", "rm", "--force", name]
    assert result["status"] == "error"
