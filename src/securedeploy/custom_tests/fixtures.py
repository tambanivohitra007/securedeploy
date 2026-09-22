"""Fixture resolver — resolves dynamic values needed by test cases."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from jinja2 import Environment as JinjaEnv
from jsonpath_ng import parse as jsonpath_parse

from securedeploy.custom_tests.models import Fixture
from securedeploy.custom_tests.auth import SessionManager

log = logging.getLogger(__name__)


class FixtureError(Exception):
    """Raised when a fixture cannot be resolved."""


class FixtureResolver:
    def __init__(
        self,
        base_url: str,
        session_manager: SessionManager,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._session_manager = session_manager
        self._resolved: dict[str, Any] = {}
        self._client = httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=False,
        )

    async def resolve_all(self, fixtures: list[Fixture]) -> dict[str, str]:
        """
        Resolve all fixtures in dependency order.
        Returns dict of {fixture_id: error_message} for any that failed.
        """
        errors: dict[str, str] = {}
        for fixture in fixtures:
            try:
                value = await self._resolve(fixture)
                self._resolved[fixture.id] = value
            except FixtureError as e:
                errors[fixture.id] = str(e)
                log.warning("Fixture '%s' failed to resolve: %s", fixture.id, e)
        return errors

    def get(self, fixture_id: str) -> Any:
        return self._resolved.get(fixture_id)

    def get_all(self) -> dict[str, Any]:
        return dict(self._resolved)

    def render_template(self, template_str: str) -> str:
        """Render a Jinja2 template with resolved fixture values."""
        env = JinjaEnv()
        tmpl = env.from_string(template_str)
        context = {"fixtures": self._resolved}
        return tmpl.render(context)

    async def _resolve(self, fixture: Fixture) -> Any:
        # Static fixture
        if fixture.value is not None:
            return fixture.value
        if fixture.resolve is None:
            return None

        resolve = fixture.resolve
        resolve_type = resolve.get("type", "static")

        if resolve_type == "static":
            return resolve.get("value")

        if resolve_type == "http_extract":
            return await self._resolve_http_extract(fixture.id, resolve)

        raise FixtureError(f"Unknown fixture resolve type: '{resolve_type}'")

    async def _resolve_http_extract(
        self, fixture_id: str, resolve: dict
    ) -> Any:
        identity_id = resolve.get("identity", "unauthenticated")
        method = resolve.get("method", "GET").upper()
        path = resolve.get("path", "/")
        extract = resolve.get("extract", "$")

        # Render path template with currently resolved fixtures
        env = JinjaEnv()
        rendered_path = env.from_string(path).render({"fixtures": self._resolved})
        url = f"{self._base_url}{rendered_path}"

        try:
            auth_headers = await self._session_manager.get_headers(identity_id)
        except Exception as e:
            raise FixtureError(f"Cannot get headers for identity '{identity_id}': {e}") from e

        try:
            resp = await self._client.request(method, url, headers=auth_headers)
        except Exception as e:
            raise FixtureError(f"HTTP request failed for fixture '{fixture_id}': {e}") from e

        if resp.status_code >= 400:
            raise FixtureError(
                f"Fixture '{fixture_id}': {method} {url} returned {resp.status_code}"
            )

        try:
            data = resp.json()
        except Exception as e:
            raise FixtureError(f"Fixture '{fixture_id}': response is not valid JSON") from e

        try:
            expr = jsonpath_parse(extract)
            matches = [m.value for m in expr.find(data)]
        except Exception as e:
            raise FixtureError(f"Fixture '{fixture_id}': JSONPath '{extract}' error: {e}") from e

        if not matches:
            raise FixtureError(
                f"Fixture '{fixture_id}': JSONPath '{extract}' matched nothing in response"
            )

        return matches[0]

    async def close(self) -> None:
        await self._client.aclose()
