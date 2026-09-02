"""Tests for nss_gtest_evaluator tool."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.nss_gtest_evaluator import nss_gtest_evaluator

from .conftest import MakeRunResult

RUN = "fx_audit_mcp.nss_gtest_evaluator.run"


@pytest.mark.anyio
async def test_clean_run_reports_no_crash(
    mocker: MockerFixture, make_run_result: MakeRunResult, firefox_dir: Path
) -> None:
    mocker.patch(
        RUN, AsyncMock(return_value=make_run_result(stdout=b"[ PASSED ] 1 test\n"))
    )

    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)

    assert result.crashed is False
    assert result.timed_out is False
    assert result.exit_code == 0


@pytest.mark.parametrize("reporting_stream", ["stdout", "stderr"])
@pytest.mark.anyio
async def test_crashdata_follows_the_stream_carrying_the_report(
    mocker: MockerFixture,
    make_run_result: MakeRunResult,
    firefox_dir: Path,
    reporting_stream: str,
) -> None:
    """Both streams have content, so crashdata must follow the reporting one."""
    report = b"==1==ERROR: AddressSanitizer: heap-use-after-free\n"
    filler = b"[ RUN      ] Suite.Test\n"
    streams = {"stdout": filler, "stderr": filler, reporting_stream: report}
    mocker.patch(RUN, AsyncMock(return_value=make_run_result(exit_code=1, **streams)))

    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)

    assert result.crashed is True
    assert result.logs.crashdata == getattr(result.logs, reporting_stream)


@pytest.mark.anyio
async def test_report_on_both_streams_lists_both_files(
    mocker: MockerFixture, make_run_result: MakeRunResult, firefox_dir: Path
) -> None:
    report = b"AddressSanitizer: stack-buffer-overflow\n"
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(exit_code=1, stdout=report, stderr=report)
        ),
    )

    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)

    assert result.logs.crashdata == [result.logs.stdout[0], result.logs.stderr[0]]


@pytest.mark.anyio
async def test_nonzero_exit_without_asan_is_gtest_error(
    mocker: MockerFixture, make_run_result: MakeRunResult, firefox_dir: Path
) -> None:
    """Verify that a failing gtest returns its output rather than raising."""
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(exit_code=1, stdout=b"[ FAILED ] Suite.Test\n")
        ),
    )

    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)

    assert result.crashed is False
    assert result.exit_code == 1
    assert result.logs.crashdata == []
    assert Path(result.logs.stdout[0]).read_bytes() == b"[ FAILED ] Suite.Test\n"


@pytest.mark.anyio
async def test_timed_out_run_is_never_a_crash(
    mocker: MockerFixture, make_run_result: MakeRunResult, firefox_dir: Path
) -> None:
    """Partial output is not scanned for a report once the run has timed out."""
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(
                exit_code=-9, timed_out=True, stderr=b"AddressSanitizer: partial\n"
            )
        ),
    )

    result = await nss_gtest_evaluator("Suite.Test", firefox_dir, timeout=1)

    assert result.timed_out is True
    assert result.crashed is False
    assert result.logs.crashdata == []


@pytest.mark.anyio
async def test_harness_invocation(
    mocker: MockerFixture, make_run_result: MakeRunResult, firefox_dir: Path
) -> None:
    """Verify the all.sh command line, working directory and environment."""
    run_mock = mocker.patch(RUN, AsyncMock(return_value=make_run_result()))

    await nss_gtest_evaluator("Suite.MyTest", firefox_dir, timeout=42)

    assert run_mock.call_args.args == (str(firefox_dir / "security/nss/tests/all.sh"),)
    kwargs = run_mock.call_args.kwargs
    assert kwargs["cwd"] == firefox_dir
    assert kwargs["timeout"] == 42
    assert kwargs["extra_env"] == {
        "DOMSUF": "localdomain",
        "HOST": "localhost",
        "NSS_TESTS": "gtests ssl_gtests",
        "NSS_CYCLES": "standard",
        "GTESTFILTER": "Suite.MyTest",
    }
