"""Tests for the bugzilla FastMCP server and tool logic."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from bugsy import BugsyException
from fastmcp.exceptions import ToolError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from fx_audit_mcp.bugzilla import (
    _log_transient_failure,
    _raise_bugsy_error,
    build_server,
    main,
)

if TYPE_CHECKING:
    from unittest.mock import MagicMock

    from pytest_mock import MockerFixture


def _make_client(
    mocker: MockerFixture,
    request_side_effect: object = None,
    request_return: object = None,
) -> MagicMock:
    client: MagicMock = mocker.MagicMock()
    if request_side_effect:
        client.request.side_effect = request_side_effect
    elif request_return is not None:
        client.request.return_value = request_return
    return client


class TestRaiseBugsyError:
    @pytest.mark.parametrize(
        ("code", "match"),
        [
            (101, "endpoint_not_exposed"),
            (102, "access_denied"),
            (500, "bugzilla_error"),
            (None, "bugzilla_error"),
        ],
    )
    def test_code_maps_to_error_kind(self, code: int | None, match: str) -> None:
        exc = BugsyException("msg")
        exc.code = code
        exc.msg = "msg"
        with pytest.raises(ToolError, match=match):
            _raise_bugsy_error(exc)


class TestSearchBugs:
    @pytest.mark.anyio
    async def test_returns_count_and_bugs(self, mocker: MockerFixture) -> None:
        client = _make_client(mocker, request_return={"bugs": [{"id": 1}, {"id": 2}]})
        result = await build_server(client).call_tool(
            "search_bugs", {"params": {"blocks": 123}}
        )
        client.request.assert_called_once_with("bug", params={"blocks": 123})
        assert result.structured_content == {
            "count": 2,
            "bugs": [{"id": 1}, {"id": 2}],
        }

    @pytest.mark.anyio
    async def test_raises_tool_error_on_bugsy_exception(
        self, mocker: MockerFixture
    ) -> None:
        exc = BugsyException("fail")
        exc.code = 500
        exc.msg = "fail"
        client = _make_client(mocker, request_side_effect=exc)
        with pytest.raises(ToolError, match="bugzilla_error"):
            await build_server(client).call_tool(
                "search_bugs", {"params": {"blocks": 1}}
            )


class TestGetBugs:
    @pytest.mark.anyio
    async def test_empty_ids_short_circuits(self, mocker: MockerFixture) -> None:
        client = _make_client(mocker)
        result = await build_server(client).call_tool("get_bugs", {"ids": []})
        assert result.structured_content is not None
        assert result.structured_content["count"] == 0
        assert result.structured_content["bugs"] == []
        assert result.structured_content["inaccessible"] == []
        client.request.assert_not_called()

    @pytest.mark.anyio
    async def test_reports_inaccessible_ids(self, mocker: MockerFixture) -> None:
        client = _make_client(mocker, request_return={"bugs": [{"id": 1}]})
        result = await build_server(client).call_tool("get_bugs", {"ids": [1, 2, 3]})
        assert result.structured_content is not None
        assert result.structured_content["count"] == 1
        assert result.structured_content["inaccessible"] == [2, 3]

    @pytest.mark.anyio
    async def test_include_fields_uses_default_when_unset(
        self, mocker: MockerFixture
    ) -> None:
        client = _make_client(mocker, request_return={"bugs": []})
        await build_server(client).call_tool("get_bugs", {"ids": [1]})
        params = client.request.call_args.kwargs["params"]
        assert "include_fields" in params
        assert "whiteboard" in params["include_fields"]

    @pytest.mark.anyio
    async def test_include_fields_passes_through(self, mocker: MockerFixture) -> None:
        client = _make_client(mocker, request_return={"bugs": []})
        await build_server(client).call_tool(
            "get_bugs", {"ids": [42], "include_fields": "id,summary"}
        )
        params = client.request.call_args.kwargs["params"]
        assert params["id"] == "42"
        assert params["include_fields"] == "id,summary"

    @pytest.mark.anyio
    async def test_include_comments_attaches_per_bug(
        self, mocker: MockerFixture
    ) -> None:
        client = _make_client(mocker)
        client.request.side_effect = [
            {"bugs": [{"id": 10}, {"id": 11}]},
            {
                "bugs": {
                    "10": {"comments": [{"text": "c1"}]},
                    "11": {"comments": [{"text": "c2"}]},
                }
            },
        ]
        result = await build_server(client).call_tool(
            "get_bugs", {"ids": [10, 11], "include_comments": True}
        )
        assert result.structured_content is not None
        bugs_by_id = {b["id"]: b for b in result.structured_content["bugs"]}
        assert bugs_by_id[10]["comments"] == [{"text": "c1"}]
        assert bugs_by_id[11]["comments"] == [{"text": "c2"}]
        assert result.structured_content["comments_error"] is None

    @pytest.mark.anyio
    async def test_comments_error_surfaced_on_partial_failure(
        self, mocker: MockerFixture
    ) -> None:
        exc = BugsyException("comment fail")
        exc.code = 102
        exc.msg = "comment fail"
        client = _make_client(mocker)
        client.request.side_effect = [{"bugs": [{"id": 10}]}, exc]
        result = await build_server(client).call_tool(
            "get_bugs", {"ids": [10], "include_comments": True}
        )
        assert result.structured_content is not None
        assert result.structured_content["count"] == 1
        assert "102" in (result.structured_content["comments_error"] or "")

    @pytest.mark.anyio
    async def test_raises_tool_error_on_main_fetch_failure(
        self, mocker: MockerFixture
    ) -> None:
        exc = BugsyException("denied")
        exc.code = 101
        exc.msg = "denied"
        client = _make_client(mocker, request_side_effect=exc)
        with pytest.raises(ToolError, match="endpoint_not_exposed"):
            await build_server(client).call_tool("get_bugs", {"ids": [1]})


class TestGetBugComments:
    @pytest.mark.anyio
    async def test_extracts_comments_by_string_id(self, mocker: MockerFixture) -> None:
        client = _make_client(
            mocker,
            request_return={"bugs": {"42": {"comments": [{"text": "hello"}]}}},
        )
        result = await build_server(client).call_tool(
            "get_bug_comments", {"bug_id": 42}
        )
        client.request.assert_called_once_with("bug/42/comment")
        assert result.structured_content == {
            "bug_id": 42,
            "count": 1,
            "comments": [{"text": "hello"}],
        }

    @pytest.mark.anyio
    async def test_raises_tool_error(self, mocker: MockerFixture) -> None:
        exc = BugsyException("oops")
        exc.code = 500
        exc.msg = "oops"
        client = _make_client(mocker, request_side_effect=exc)
        with pytest.raises(ToolError, match="bugzilla_error"):
            await build_server(client).call_tool("get_bug_comments", {"bug_id": 1})


class TestGetBugAttachments:
    @pytest.mark.anyio
    async def test_default_excludes_data_field(self, mocker: MockerFixture) -> None:
        client = _make_client(mocker, request_return={"bugs": {"7": []}})
        await build_server(client).call_tool("get_bug_attachments", {"bug_id": 7})
        client.request.assert_called_once_with(
            "bug/7/attachment", params={"exclude_fields": "data"}
        )

    @pytest.mark.anyio
    async def test_include_data_drops_exclude(self, mocker: MockerFixture) -> None:
        client = _make_client(mocker, request_return={"bugs": {"7": []}})
        await build_server(client).call_tool(
            "get_bug_attachments", {"bug_id": 7, "include_data": True}
        )
        client.request.assert_called_once_with("bug/7/attachment", params={})

    @pytest.mark.anyio
    async def test_extracts_attachments_by_string_id(
        self, mocker: MockerFixture
    ) -> None:
        client = _make_client(
            mocker,
            request_return={"bugs": {"7": [{"id": 100, "file_name": "test.html"}]}},
        )
        result = await build_server(client).call_tool(
            "get_bug_attachments", {"bug_id": 7}
        )
        assert result.structured_content is not None
        assert result.structured_content["bug_id"] == 7
        assert result.structured_content["count"] == 1
        assert result.structured_content["attachments"][0]["file_name"] == "test.html"

    @pytest.mark.anyio
    async def test_raises_tool_error(self, mocker: MockerFixture) -> None:
        exc = BugsyException("nope")
        exc.code = 101
        exc.msg = "nope"
        client = _make_client(mocker, request_side_effect=exc)
        with pytest.raises(ToolError, match="endpoint_not_exposed"):
            await build_server(client).call_tool("get_bug_attachments", {"bug_id": 1})


class TestLogTransientFailure:
    @staticmethod
    def _make_response(
        mocker: MockerFixture,
        status_code: int,
        url: str = "https://example.test/rest/bug",
        headers: dict[str, str] | None = None,
        text: str = "",
        elapsed_seconds: float = 0.0,
    ) -> MagicMock:
        response: MagicMock = mocker.MagicMock()
        response.status_code = status_code
        response.url = url
        response.headers = headers or {}
        response.text = text
        response.elapsed = timedelta(seconds=elapsed_seconds)
        return response

    @pytest.mark.parametrize("status", [200, 301, 404, 499])
    def test_non_5xx_does_not_log(
        self,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ) -> None:
        response = self._make_response(mocker, status)
        with caplog.at_level(logging.WARNING, logger="fx_audit_mcp.bugzilla"):
            result = _log_transient_failure(response)
        assert result is response
        assert caplog.records == []

    @pytest.mark.parametrize(
        "key_param",
        ["Bugzilla_api_key", "bugzilla_api_key"],
    )
    def test_redacts_api_key_in_url(
        self,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
        key_param: str,
    ) -> None:
        response = self._make_response(
            mocker,
            502,
            url=f"https://example.test/rest/bug?{key_param}=SECRETKEY&id=1",
            text="upstream request timeout",
            elapsed_seconds=1.5,
        )
        with caplog.at_level(logging.WARNING, logger="fx_audit_mcp.bugzilla"):
            _log_transient_failure(response)
        assert len(caplog.records) == 1
        message = caplog.records[0].getMessage()
        assert "SECRETKEY" not in message
        assert f"{key_param}=REDACTED" in message
        assert "id=1" in message

    def test_logs_diagnostic_headers_only(
        self,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        response = self._make_response(
            mocker,
            504,
            headers={
                "Server": "heroku",
                "Via": "1.1 vegur",
                "X-Heroku-Queue-Wait-Time": "42",
                "Content-Type": "text/plain",
                "Set-Cookie": "session=secret",
            },
        )
        with caplog.at_level(logging.WARNING, logger="fx_audit_mcp.bugzilla"):
            _log_transient_failure(response)
        message = caplog.records[0].getMessage()
        assert "Server" in message
        assert "Via" in message
        assert "X-Heroku-Queue-Wait-Time" in message
        assert "Content-Type" not in message
        assert "Set-Cookie" not in message

    def test_truncates_long_body(
        self,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        response = self._make_response(mocker, 503, text="x" * 1000)
        with caplog.at_level(logging.WARNING, logger="fx_audit_mcp.bugzilla"):
            _log_transient_failure(response)
        message = caplog.records[0].getMessage()
        assert "x" * 200 in message
        assert "x" * 201 not in message


class TestMain:
    def test_missing_api_key_exits_nonzero(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("BUGZILLA_API_KEY", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        assert "BUGZILLA_API_KEY" in capsys.readouterr().err

    def test_happy_path_runs_server(
        self,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("BUGZILLA_API_KEY", "secret")
        monkeypatch.setenv("BUGZILLA_URL", "https://example.test/rest")
        bugsy_ctor: MagicMock = mocker.patch("fx_audit_mcp.bugzilla.bugsy.Bugsy")
        fake_server: MagicMock = mocker.MagicMock()
        build_server_mock: MagicMock = mocker.patch(
            "fx_audit_mcp.bugzilla.build_server", return_value=fake_server
        )
        main()
        bugsy_ctor.assert_called_once_with(
            api_key="secret", bugzilla_url="https://example.test/rest"
        )
        build_server_mock.assert_called_once_with(bugsy_ctor.return_value)
        fake_server.run.assert_called_once_with(transport="stdio", show_banner=False)

    def test_main_mounts_retry_adapter_and_response_hook(
        self,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("BUGZILLA_API_KEY", "secret")
        bugsy_ctor: MagicMock = mocker.patch("fx_audit_mcp.bugzilla.bugsy.Bugsy")
        client = bugsy_ctor.return_value
        client.session.hooks = {"response": []}
        mocker.patch("fx_audit_mcp.bugzilla.build_server")
        main()
        schemes = [c.args[0] for c in client.session.mount.call_args_list]
        assert schemes == ["http://", "https://"]
        adapters = {c.args[0]: c.args[1] for c in client.session.mount.call_args_list}
        assert adapters["http://"] is adapters["https://"]
        adapter = adapters["https://"]
        assert isinstance(adapter, HTTPAdapter)
        retry = adapter.max_retries
        assert isinstance(retry, Retry)
        assert retry.total == 5
        assert retry.backoff_factor == 2
        assert set(retry.status_forcelist or ()) == {429, 500, 502, 503, 504}
        assert retry.allowed_methods == frozenset({"GET"})
        assert retry.raise_on_status is False
        assert retry.respect_retry_after_header is True
        assert _log_transient_failure in client.session.hooks["response"]

    def test_keyboard_interrupt_exits_zero(
        self,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("BUGZILLA_API_KEY", "secret")
        mocker.patch("fx_audit_mcp.bugzilla.bugsy.Bugsy")
        fake_server: MagicMock = mocker.MagicMock()
        fake_server.run.side_effect = KeyboardInterrupt
        mocker.patch("fx_audit_mcp.bugzilla.build_server", return_value=fake_server)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_unexpected_exception_exits_nonzero(
        self,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("BUGZILLA_API_KEY", "secret")
        mocker.patch("fx_audit_mcp.bugzilla.bugsy.Bugsy")
        fake_server: MagicMock = mocker.MagicMock()
        fake_server.run.side_effect = RuntimeError("boom")
        mocker.patch("fx_audit_mcp.bugzilla.build_server", return_value=fake_server)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        assert "boom" in capsys.readouterr().err
