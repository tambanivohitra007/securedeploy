"""Pydantic models for custom security test definitions."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AuthType(str, Enum):
    NONE = "none"
    LOGIN_FORM = "login_form"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC = "basic"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"


class TokenUsage(BaseModel):
    header: str = "Authorization"
    prefix: str = "Bearer "
    cookie: str | None = None
    query_param: str | None = None


class IdentityAuth(BaseModel):
    type: AuthType = AuthType.NONE
    # login_form / oauth2
    url: str | None = None
    method: str = "POST"
    body: dict[str, Any] = Field(default_factory=dict)
    token_path: str | None = None  # JSONPath to token in response
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    # api_key / bearer_token
    header: str | None = None
    value: str | None = None
    # basic
    username: str | None = None
    password: str | None = None
    # oauth2_client_credentials
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None


class Identity(BaseModel):
    id: str
    auth: IdentityAuth = Field(default_factory=IdentityAuth)


class IdentitiesFile(BaseModel):
    identities: list[Identity] = Field(default_factory=list)


class FixtureResolveHttp(BaseModel):
    type: str = "http_extract"
    identity: str = "unauthenticated"
    method: str = "GET"
    path: str
    extract: str  # JSONPath


class FixtureResolveStatic(BaseModel):
    type: str = "static"


class Fixture(BaseModel):
    id: str
    description: str = ""
    value: Any | None = None  # for static fixtures
    resolve: dict[str, Any] | None = None  # for http_extract


class FixturesFile(BaseModel):
    fixtures: list[Fixture] = Field(default_factory=list)


class RequestSpec(BaseModel):
    method: str = "GET"
    path: str
    body: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    protocol: str | None = None  # override scheme: "http" or "https"


class SetCookieAssertion(BaseModel):
    all: dict[str, Any] | None = None   # flags all cookies must have
    name: str | None = None              # specific cookie name


class HeaderAssertion(BaseModel):
    present: bool | None = None
    contains: str | None = None
    starts_with: str | None = None
    min_max_age: int | None = None
    must_not_contain: str | None = None


class ExpectSpec(BaseModel):
    status: int | list[int] | None = None
    body_must_contain: list[str] = Field(default_factory=list)
    body_must_not_contain: list[str] = Field(default_factory=list)
    headers: dict[str, HeaderAssertion] = Field(default_factory=dict)
    set_cookie: SetCookieAssertion | None = None
    # Follow-up request after main assertion
    follow_up: "FollowUp | None" = None


class FollowUp(BaseModel):
    request: RequestSpec
    expect: ExpectSpec


ExpectSpec.model_rebuild()


class AuthorizationTest(BaseModel):
    name: str
    severity: str = "high"
    identity: str = "unauthenticated"
    request: RequestSpec
    expect: ExpectSpec
    skip: bool = False


class AuthorizationTestSuite(BaseModel):
    suite: str = "Authorization Tests"
    category: str = "Broken Access Control"
    owasp: str = "WSTG-ATHZ-01"
    cwe: str = "CWE-285"
    authorization_tests: list[AuthorizationTest] = Field(default_factory=list)
    header_tests: list[AuthorizationTest] = Field(default_factory=list)


class TestResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"
