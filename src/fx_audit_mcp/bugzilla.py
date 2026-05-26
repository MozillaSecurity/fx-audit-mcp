"""Read-only FastMCP server wrapping bugsy for Bugzilla REST access.

Spawned over stdio by the ``fx-audit-bugzilla-mcp`` console script. Reads
``BUGZILLA_API_KEY`` (required) and ``BUGZILLA_URL`` (defaults to the public
Mozilla instance) from the environment.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import TYPE_CHECKING, Any, NoReturn

import bugsy
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import (
    BugzillaAttachmentsResult,
    BugzillaCommentsResult,
    BugzillaGetBugsResult,
    BugzillaSearchResult,
)

if TYPE_CHECKING:
    import requests

DEFAULT_INCLUDE_FIELDS = (
    "id,summary,status,resolution,product,component,priority,"
    "severity,keywords,whiteboard,assigned_to,creator,"
    "creation_time,last_change_time,blocks,depends_on,see_also,"
    "cf_crash_signature,url,version,op_sys,platform"
)

logger = logging.getLogger("fx_audit_mcp.bugzilla")

_API_KEY_QUERY_RE = re.compile(r"(Bugzilla_api_key=)[^&]*", re.IGNORECASE)

_DIAG_HEADERS = (
    "Server",
    "Via",
    "X-Heroku-Queue-Wait-Time",
    "X-Bugzilla-Run",
    "Cache-Status",
    "CF-Ray",
    "Age",
)


def _log_transient_failure(
    response: requests.Response, *_args: object, **_kwargs: object
) -> requests.Response:
    """Session hook: emit timing + headers + body on any 5xx response.

    Bugsy raises a generic BugsyException on 5xx that swallows the URL,
    timing, and gateway headers. This hook logs them on the way through so a
    captured stderr log is enough to reconstruct the failing call. The API
    key (which bugsy puts in the URL for Bugzilla 5.0 compat) is redacted
    before logging.
    """
    if response.status_code < 500:
        return response
    safe_url = _API_KEY_QUERY_RE.sub(r"\1REDACTED", response.url)
    headers = {k: response.headers[k] for k in _DIAG_HEADERS if k in response.headers}
    logger.warning(
        "bugzilla %d in %.2fs url=%s headers=%s body=%s",
        response.status_code,
        response.elapsed.total_seconds(),
        safe_url,
        headers,
        response.text[:200],
    )
    return response


def _raise_bugsy_error(e: bugsy.BugsyException) -> NoReturn:
    """Translate a bugsy exception into a FastMCP ``ToolError``.

    Raising surfaces ``isError=True`` at the protocol level (rather than
    burying the failure as data the agent has to introspect). Friendly hints
    are folded into the message for the common policy/access codes.

    Args:
        e: Bugsy exception raised by a REST call.

    Raises:
        ToolError: Always; never returns.
    """
    code = getattr(e, "code", None)
    msg = getattr(e, "msg", str(e))
    if code == 101:
        raise ToolError(f"endpoint_not_exposed (code=101): {msg}")
    if code == 102:
        raise ToolError(
            f"access_denied (code=102): {msg}. Your API key cannot access this "
            "bug; skip it."
        )
    raise ToolError(f"bugzilla_error (code={code}): {msg}")


def build_server(client: bugsy.Bugsy) -> FastMCP:
    """Create a FastMCP server with the four bugzilla tools bound to *client*.

    Tool descriptions and parameter schemas come from each tool's docstring
    and type hints; FastMCP introspects them at registration.

    Args:
        client: Bugsy client to bind into each tool's closure.

    Returns:
        A FastMCP server named ``bugzilla``.
    """
    mcp = FastMCP("bugzilla", version="0.1.0")

    async def _search_bugs(params: dict[str, Any]) -> BugzillaSearchResult:
        """Search Bugzilla for bugs by metadata (product, component, keywords,
        status, blocks, etc.) using raw REST query parameters.

        Args:
            params: Bugzilla REST /bug query parameters; values are ANDed
                together. Common keys: id, keywords, blocks, depends_on,
                product, component, status, resolution, priority, severity,
                assigned_to, whiteboard, include_fields, limit. Examples:
                ``{"blocks": 12345, "keywords": "sec-low"}``,
                ``{"product": "Core", "status": "NEW", "limit": 50}``.

        Raises:
            ToolError: If the underlying bugsy call fails.
        """
        try:
            result = client.request("bug", params=params)
        except bugsy.BugsyException as e:
            _raise_bugsy_error(e)
        bugs = result.get("bugs", [])
        return BugzillaSearchResult(count=len(bugs), bugs=bugs)

    async def _get_bugs(
        ids: list[int],
        include_fields: str | None = None,
        include_comments: bool = False,
    ) -> BugzillaGetBugsResult:
        """Fetch Bugzilla bug records by ID in a single bulk request;
        optionally pulls all comments inline as well.

        A partial failure on the comment side-fetch is reported on the payload
        rather than raised; the main bug-fetch failure is raised.

        Args:
            ids: Bug IDs to fetch.
            include_fields: Comma-separated field list, or ``_default`` /
                ``_all``. Defaults to a sensible triage set. Request
                whiteboard/keywords explicitly if needed.
            include_comments: If true, also bulk-fetch comments in one extra
                request and attach them per bug.

        Raises:
            ToolError: If the main bug fetch fails.
        """
        if not ids:
            return BugzillaGetBugsResult(count=0, bugs=[], inaccessible=[])
        include = include_fields or DEFAULT_INCLUDE_FIELDS
        id_csv = ",".join(str(i) for i in ids)
        try:
            result = client.request(
                "bug", params={"id": id_csv, "include_fields": include}
            )
        except bugsy.BugsyException as e:
            _raise_bugsy_error(e)
        bugs = result.get("bugs", [])
        returned = {b["id"] for b in bugs}
        inaccessible = [i for i in ids if i not in returned]
        comments_error: str | None = None

        if include_comments and bugs:
            first, *rest = [b["id"] for b in bugs]
            cparams = {"ids": ",".join(str(i) for i in rest)} if rest else {}
            try:
                cres = client.request(f"bug/{first}/comment", params=cparams)
            except bugsy.BugsyException as e:
                # Comments are commonly inaccessible (code 102) on restricted
                # bugs even when the bug fields themselves are readable;
                # degrade gracefully and surface the error on the payload
                # rather than failing the whole call.
                code = getattr(e, "code", None)
                msg = getattr(e, "msg", str(e))
                comments_error = f"bugzilla_error (code={code}): {msg}"
            else:
                comments_by_bug = {
                    int(bid): data["comments"]
                    for bid, data in cres.get("bugs", {}).items()
                }
                for b in bugs:
                    b["comments"] = comments_by_bug.get(b["id"], [])

        return BugzillaGetBugsResult(
            count=len(bugs),
            bugs=bugs,
            inaccessible=inaccessible,
            comments_error=comments_error,
        )

    async def _get_bug_comments(bug_id: int) -> BugzillaCommentsResult:
        """Fetch all comments for a single bug.

        Args:
            bug_id: Bug ID whose comments to fetch.

        Raises:
            ToolError: If the underlying bugsy call fails.
        """
        try:
            result = client.request(f"bug/{bug_id}/comment")
        except bugsy.BugsyException as e:
            _raise_bugsy_error(e)
        comments = result.get("bugs", {}).get(str(bug_id), {}).get("comments", [])
        return BugzillaCommentsResult(
            bug_id=bug_id, count=len(comments), comments=comments
        )

    async def _get_bug_attachments(
        bug_id: int,
        include_data: bool = False,
    ) -> BugzillaAttachmentsResult:
        """Fetch attachment metadata for a Bugzilla bug; pass
        include_data=True to also get the base64-encoded content.

        Returns metadata only unless ``include_data`` is set; attachment
        payloads can be large.

        Args:
            bug_id: Bug ID whose attachments to fetch.
            include_data: If true, include base64-encoded attachment content.
                Attachments can be large; default is metadata only.

        Raises:
            ToolError: If the underlying bugsy call fails.
        """
        params = {} if include_data else {"exclude_fields": "data"}
        try:
            result = client.request(f"bug/{bug_id}/attachment", params=params)
        except bugsy.BugsyException as e:
            _raise_bugsy_error(e)
        atts = result.get("bugs", {}).get(str(bug_id), [])
        return BugzillaAttachmentsResult(
            bug_id=bug_id, count=len(atts), attachments=atts
        )

    mcp.tool(_search_bugs, name="search_bugs")
    mcp.tool(_get_bugs, name="get_bugs")
    mcp.tool(_get_bug_comments, name="get_bug_comments")
    mcp.tool(_get_bug_attachments, name="get_bug_attachments")
    return mcp


def main() -> None:
    """Entry point for ``fx-audit-bugzilla-mcp``.

    Reads ``BUGZILLA_API_KEY`` (required) and ``BUGZILLA_URL`` (optional,
    defaults to the public Mozilla instance) from the environment, then
    serves the bugzilla MCP tools over stdio.
    """
    api_key = os.environ.get("BUGZILLA_API_KEY")
    if not api_key:
        print("BUGZILLA_API_KEY env var is required", file=sys.stderr)
        sys.exit(1)
    bz_url = os.environ.get("BUGZILLA_URL", "https://bugzilla.mozilla.org/rest")
    client = bugsy.Bugsy(api_key=api_key, bugzilla_url=bz_url)
    # Retry transient 5xx / 429 on GET-only requests. fx-audit-mcp is
    # read-only -- every tool issues GET -- so blind retries are safe (no risk
    # of duplicate writes). Do not widen allowed_methods without adding
    # idempotency checks at each call site.
    retry = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    client.session.mount("http://", adapter)
    client.session.mount("https://", adapter)
    client.session.hooks["response"].append(_log_transient_failure)
    server = build_server(client)
    try:
        server.run(transport="stdio", show_banner=False)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Error running bugzilla MCP server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
