"""Identity and session manager for custom tests.

Performs authentication flows once per identity, caches tokens for the
duration of the scan. Credentials are never logged.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from jsonpath_ng import parse as jsonpath_parse

from securedeploy.custom_tests.models import AuthType, Identity
from securedeploy.utils.redact import redact

log = logging.getLogger(__name__)


class AuthError(Exception):
    """Authentication flow failed."""


class SessionManager:
    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._sessions: dict[str, dict[str, str]] = {}  # id → {header_name: header_value}
        self._identities: dict[str, Identity] = {}
        self._client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=False,  # staging may use self-signed certs
        )

    def register(self, identity: Identity) -> None:
        self._identities[identity.id] = identity

    async def authenticate_all(self) -> dict[str, str]:
        """
        Authenticate all registered identities.
        Returns dict of {identity_id: error_message} for any that failed.
        """
        errors: dict[str, str] = {}
        for identity_id, identity in self._identities.items():
            if identity.auth.type == AuthType.NONE:
                self._sessions[identity_id] = {}
                continue
            try:
                headers = await self._authenticate(identity)
                self._sessions[identity_id] = headers
                log.debug("Authenticated identity: %s", identity_id)
            except AuthError as e:
                errors[identity_id] = str(e)
                log.warning("Authentication failed for %s: %s", identity_id, e)
        return errors

    async def get_headers(self, identity_id: str) -> dict[str, str]:
        """Return auth headers for an identity. Raises AuthError if not authenticated."""
        if identity_id not in self._sessions:
            if identity_id not in self._identities:
                raise AuthError(f"Unknown identity: '{identity_id}'")
            # Try to authenticate on demand
            identity = self._identities[identity_id]
            headers = await self._authenticate(identity)
            self._sessions[identity_id] = headers
        return self._sessions[identity_id]

    async def _authenticate(self, identity: Identity) -> dict[str, str]:
        auth = identity.auth
        if auth.type == AuthType.NONE:
            return {}

        if auth.type == AuthType.API_KEY:
            if not auth.header or not auth.value:
                raise AuthError(f"api_key identity requires 'header' and 'value'")
            return {auth.header: auth.value}

        if auth.type == AuthType.BEARER_TOKEN:
            if not auth.value:
                raise AuthError("bearer_token identity requires 'value'")
            prefix = auth.token_usage.prefix if auth.token_usage else "Bearer "
            header = auth.token_usage.header if auth.token_usage else "Authorization"
            return {header: f"{prefix}{auth.value}"}

        if auth.type == AuthType.BASIC:
            import base64
            credentials = base64.b64encode(
                f"{auth.username}:{auth.password}".encode()
            ).decode()
            return {"Authorization": f"Basic {credentials}"}

        if auth.type in (AuthType.LOGIN_FORM, AuthType.OAUTH2_CLIENT_CREDENTIALS):
            return await self._token_flow(identity)

        raise AuthError(f"Unsupported auth type: {auth.type}")

    async def _token_flow(self, identity: Identity) -> dict[str, str]:
        auth = identity.auth
        url = f"{self._base_url}{auth.url}" if auth.url and auth.url.startswith("/") else (auth.url or "")

        if auth.type == AuthType.OAUTH2_CLIENT_CREDENTIALS:
            body = {
                "grant_type": "client_credentials",
                "client_id": auth.client_id or "",
                "client_secret": auth.client_secret or "",
            }
            if auth.scope:
                body["scope"] = auth.scope
        else:
            body = dict(auth.body)

        try:
            resp = await self._client.request(
                auth.method,
                url,
                json=body,
            )
        except Exception as e:
            raise AuthError(f"HTTP request to {url} failed: {e}") from e

        if resp.status_code >= 400:
            raise AuthError(
                f"Auth request to {url} returned {resp.status_code}. "
                "Check credentials in environment variables."
            )

        # Extract token from response using JSONPath
        if auth.token_path:
            try:
                data = resp.json()
                expr = jsonpath_parse(auth.token_path)
                matches = [m.value for m in expr.find(data)]
                if not matches:
                    raise AuthError(
                        f"token_path '{auth.token_path}' not found in auth response"
                    )
                token = str(matches[0])
            except AuthError:
                raise
            except Exception as e:
                raise AuthError(f"Failed to extract token: {e}") from e

            usage = auth.token_usage
            if usage.cookie:
                # Session cookie set by server — use cookie jar
                return {}  # httpx will handle cookies automatically
            header_name = usage.header
            prefix = usage.prefix
            return {header_name: f"{prefix}{token}"}

        # No token_path — assume session cookie was set
        return {}

    async def close(self) -> None:
        await self._client.aclose()
