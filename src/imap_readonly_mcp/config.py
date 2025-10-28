"""Configuration models for the read-only email MCP server."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import ConfigurationError


class AccountProtocol(str, Enum):
    """Supported email access protocols."""

    IMAP = "imap"
    POP3 = "pop3"
    GRAPH = "graph"


class OAuth2GrantType(str, Enum):
    """Supported OAuth2 grant types."""

    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    AUTHORIZATION_CODE = "authorization_code"


class OAuth2Config(BaseModel):
    """Generic OAuth2 configuration for connectors that support it."""

    authority: str | None = Field(
        default=None,
        description="OAuth2 authority / issuer URL (e.g. https://login.microsoftonline.com/{tenant}).",
    )
    token_url: str | None = Field(
        default=None, description="Explicit token endpoint URL if it cannot be derived from the authority."
    )
    client_id: str = Field(description="OAuth2 client identifier.")
    client_secret: SecretStr | None = Field(
        default=None,
        description="OAuth2 client secret, required for confidential clients unless device/broker flow is used.",
    )
    scopes: list[str] = Field(default_factory=list, description="Scope list to request when exchanging tokens.")
    grant_type: OAuth2GrantType = Field(
        default=OAuth2GrantType.CLIENT_CREDENTIALS, description="OAuth2 grant type to request tokens."
    )
    tenant_id: str | None = Field(
        default=None,
        description="Optional tenant identifier (for Microsoft identity platforms).",
    )
    user_id: str | None = Field(
        default=None,
        description="Optional user principal (email address or ID) used when a grant requires a user context.",
    )
    device_code_prompt: bool = Field(
        default=False, description="If true, triggers device code flow instructions in the logs."
    )

    @model_validator(mode="after")
    def _validate_secret(self) -> "OAuth2Config":
        if self.grant_type == OAuth2GrantType.CLIENT_CREDENTIALS and not self.client_secret:
            raise ConfigurationError("client_secret is required for client_credentials grant")
        return self



class AccountRateLimit(BaseModel):
    """Simple rate limiting configuration for connectors that require throttling."""

    max_requests: int = Field(default=120, description="Maximum requests during the period.")
    period_seconds: int = Field(default=60, description="Window length for rate limiting in seconds.")

    @model_validator(mode="after")
    def _ensure_positive(self) -> "AccountRateLimit":
        if self.max_requests < 1 or self.period_seconds < 1:
            raise ConfigurationError("Rate limit must have positive max_requests and period_seconds")
        return self


class ConnectorSecurityConfig(BaseModel):
    """Transport security toggles that apply to IMAP/POP3 connectors."""

    use_ssl: bool = Field(default=True, description="Whether to use implicit TLS from the beginning of the connection.")
    starttls: bool = Field(default=False, description="Whether to upgrade the connection with STARTTLS.")
    verify_ssl: bool = Field(default=True, description="If false, SSL certificate verification is disabled (not safe).")


class MailAccountConfig(BaseModel):
    """Configuration for a single email account exposed through the server."""

    id: str = Field(description="Unique identifier to reference the account from tools.")
    protocol: AccountProtocol = Field(description="Protocol used to access this mailbox.")
    description: str | None = Field(default=None, description="Human readable description of the account.")

    # Common connection parameters
    host: str | None = Field(default=None, description="Mail server host (not required for Microsoft Graph).")
    port: int | None = Field(default=None, description="Server port. Defaults depend on the protocol.")
    username: str | None = Field(default=None, description="Username for authenticating to the server.")
    password: SecretStr | None = Field(default=None, description="Password for authenticating to the server.")
    security: ConnectorSecurityConfig = Field(
        default_factory=ConnectorSecurityConfig, description="Transport security options."
    )
    timeout_seconds: float = Field(default=30.0, ge=5.0, le=180.0, description="Socket timeout used by the connector.")
    default_folder: str | None = Field(
        default=None,
        description="Preferred default folder/mailbox to use when none is explicitly supplied.",
    )
    allowed_folders: list[str] | None = Field(
        default=None,
        description="Optional allow-list of folders that can be accessed via the server.",
    )
    excluded_folders: list[str] | None = Field(
        default=None,
        description="Optional block-list of folders that will never be exposed to clients.",
    )

    # Optional OAuth2 parameters for connectors that support it
    oauth: OAuth2Config | None = Field(
        default=None, description="OAuth2 configuration when password based login is not desired."
    )

    # Optional throttling configuration
    rate_limit: AccountRateLimit | None = Field(
        default=None, description="Optional rate limiting applied per account."
    )

    # Protocol-specific hints
    graph_resource: Literal["me", "users"] = Field(
        default="me",
        description="When using Microsoft Graph, determines if the connector calls /me or /users/{user_id}.",
    )

    tenant_domain: str | None = Field(
        default=None,
        description="For Microsoft Graph: the tenant domain if not inferrable from login credentials.",
    )

    google_service_account_json: Path | None = Field(
        default=None,
        description="Optional path to a Google service account JSON credentials file for Gmail API access.",
    )

    @model_validator(mode="after")
    def _validate_protocol_specifics(self) -> "MailAccountConfig":
        if self.protocol in {AccountProtocol.IMAP, AccountProtocol.POP3}:
            if not self.host:
                raise ConfigurationError(f"host is required for {self.protocol.value} accounts ({self.id})")
            if not self.username:
                raise ConfigurationError(f"username is required for {self.protocol.value} accounts ({self.id})")
            if not self.password:
                raise ConfigurationError(
                    f"password must be provided for {self.protocol.value} account {self.id} to ensure read-only login"
                )
        if self.protocol is AccountProtocol.GRAPH:
            if not self.oauth:
                raise ConfigurationError("OAuth configuration is required for Microsoft Graph accounts")
            if self.oauth.grant_type not in {
                OAuth2GrantType.CLIENT_CREDENTIALS,
                OAuth2GrantType.AUTHORIZATION_CODE,
                OAuth2GrantType.DEVICE_CODE,
            }:
                raise ConfigurationError("Unsupported grant type for Microsoft Graph connector")
        return self


class MailSettings(BaseSettings):
    """Top-level configuration container for the server."""

    model_config = SettingsConfigDict(
        env_prefix="MAIL_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
    )

    account: MailAccountConfig = Field(description="Single account exposed by the server.")
    default_search_limit: int = Field(default=50, gt=0, description="Default limit applied to message search results.")
    maximum_search_limit: int = Field(default=200, gt=0, description="Hard limit to protect accidental large searches.")
    connection_retries: int = Field(
        default=3, ge=0, le=10, description="Number of times the server will retry failed connector operations."
    )

    config_path: Path | None = Field(
        default=None,
        description="Resolved path used to load configuration (for diagnostics).",
        exclude=True,
    )

def load_settings(config_path: Path | None = None, overrides: dict[str, Any] | None = None) -> MailSettings:
    """Load configuration from YAML/JSON on disk combined with environment overrides."""

    base_data: dict[str, Any] = {}
    resolved_path: Path | None = None
    if config_path:
        resolved_path = Path(config_path).expanduser().resolve()
        if not resolved_path.exists():
            raise ConfigurationError(f"Configuration file not found: {resolved_path}")
        try:
            with resolved_path.open("r", encoding="utf-8") as handle:
                base_data = yaml.safe_load(handle.read()) or {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Unable to parse configuration file {resolved_path}: {exc}") from exc
    if overrides:
        base_data.update(overrides)

    if "account" not in base_data:
        legacy_accounts = base_data.get("accounts")
        if legacy_accounts:
            base_data["account"] = legacy_accounts[0]
        else:
            raise ConfigurationError("Configuration must specify 'account'.")
    base_data.pop("accounts", None)

    settings = MailSettings.model_validate(base_data)
    settings.config_path = resolved_path
    return settings
