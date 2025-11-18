"""Microsoft Graph connector implementation."""

from __future__ import annotations

import base64
import time
from typing import Any

from ..config import MailAccountConfig
from ..exceptions import AttachmentNotFoundError, ConnectorNotAvailableError, MessageNotFoundError
from ..models import (
    AttachmentContent,
    AttachmentMetadata,
    FolderInfo,
    MailboxRole,
    MessageBody,
    MessageDetail,
    MessageFlags,
    MessageSearchFilters,
    MessageSummary,
)
from ..utils.email_parser import parse_address_list
from ..utils.identifiers import encode_folder_path
from .base import ConnectorCapabilities, ReadOnlyMailConnector

GRAPH_API_ROOT = "https://graph.microsoft.com/v1.0"


class GraphReadOnlyConnector(ReadOnlyMailConnector):
    """Connector that reads mail via the Microsoft Graph API."""

    def __init__(self, config: MailAccountConfig) -> None:
        super().__init__(config)
        if not config.oauth:
            raise ConnectorNotAvailableError("Microsoft Graph accounts require OAuth configuration.")
        try:
            import msal  # type: ignore
            import requests  # type: ignore
        except ImportError as exc:  # pragma: no cover - informative error path
            raise ConnectorNotAvailableError(
                "Optional dependencies for Microsoft Graph are missing. "
                "Install the project with the 'graph' extra to enable this connector."
            ) from exc
        self._msal = msal
        self._requests = requests
        self._session = requests.Session()
        self._token: dict[str, Any] | None = None
        self._token_acquired_at: float = 0.0
        self._cca = self._build_app()
        self._resource_path = _build_resource_path(config)

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            supports_folders=True,
            supports_search=True,
            supports_attachments=True,
        )

    def list_folders(self) -> list[FolderInfo]:
        url = f"{GRAPH_API_ROOT}/{self._resource_path}/mailFolders?$top=200"
        response = self._session.get(url, headers=self._headers())
        response.raise_for_status()
        data = response.json()
        folders: list[FolderInfo] = []
        for item in data.get("value", []):
            folder_id = item["id"]
            display = item.get("displayName", folder_id)
            folders.append(
                FolderInfo(
                    path=folder_id,
                    encoded_path=encode_folder_path(folder_id),
                    role=_infer_folder_role(display),
                    selectable=True,
                    total_messages=item.get("totalItemCount"),
                    unread_messages=item.get("unreadItemCount"),
                )
            )
        return folders

    def search_messages(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        url = _build_messages_url(GRAPH_API_ROOT, self._resource_path, filters.folder)
        params = _build_query_params(filters)
        headers = self._headers(consistency=bool(params.get("$search")))
        response = self._session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        messages: list[MessageSummary] = []
        for item in data.get("value", []):
            summary = self._convert_message_summary(item, filters.folder)
            messages.append(summary)
        return messages

    def fetch_message(self, folder_path: str, uid: str) -> MessageDetail:
        url = f"{GRAPH_API_ROOT}/{self._resource_path}/messages/{uid}"
        params = {
            "$select": ",".join(
                [
                    "id",
                    "body",
                    "bodyPreview",
                    "subject",
                    "from",
                    "toRecipients",
                    "ccRecipients",
                    "bccRecipients",
                    "replyTo",
                    "receivedDateTime",
                    "sentDateTime",
                    "hasAttachments",
                    "internetMessageHeaders",
                    "isRead",
                    "isDraft",
                ]
            ),
            "$expand": "attachments($select=id,name,contentType,contentBytes,size)",
        }
        headers = self._headers()
        headers["Prefer"] = 'outlook.body-content-type="text"'
        response = self._session.get(url, headers=headers, params=params)
        if response.status_code == 404:
            raise MessageNotFoundError(f"Message {uid} not found in Graph mailbox")
        response.raise_for_status()
        payload = response.json()
        summary = self._convert_message_summary(payload, payload.get("parentFolderId"))
        body = MessageBody(
            text=(payload.get("body") or {}).get("content"),
            html=None,
            charset="utf-8",
        )

        # Ensure we enumerate all attachments using the attachments endpoint (handles paging)
        attachments: list[AttachmentMetadata] = []
        if payload.get("hasAttachments"):
            att_url = f"{GRAPH_API_ROOT}/{self._resource_path}/messages/{uid}/attachments?$top=200"
            while att_url:
                att_resp = self._session.get(att_url, headers=headers)
                att_resp.raise_for_status()
                att_data = att_resp.json()
                for att in att_data.get("value", []):
                    att_id = att.get("id")
                    attachments.append(
                        AttachmentMetadata(
                            attachment_id=att_id,
                            filename=att.get("name") or "attachment",
                            content_type=att.get("contentType", "application/octet-stream"),
                            size=att.get("size"),
                            resource_uri=f"mail+attachment://{summary.folder_token}/{summary.uid}/{att_id}",
                        )
                    )
                next_link = att_data.get("@odata.nextLink")
                att_url = str(next_link) if next_link else ""

        headers_map: dict[str, list[str]] = {}
        for header in payload.get("internetMessageHeaders", []):
            name = header.get("name") or ""
            value = header.get("value")
            if value is None:
                value = ""
            else:
                value = str(value)
            headers_map.setdefault(name, []).append(value)

        detail = MessageDetail(
            **summary.model_dump(),
            body=body,
            attachments=attachments,
            headers=headers_map,
            raw_source=None,
        )
        return detail

    def fetch_raw_message(self, folder_path: str, uid: str) -> bytes:
        url = f"{GRAPH_API_ROOT}/{self._resource_path}/messages/{uid}/$value"
        response = self._session.get(url, headers=self._headers(), stream=True)
        if response.status_code == 404:
            raise MessageNotFoundError(f"Message {uid} not found in Graph mailbox")
        response.raise_for_status()
        return response.content

    def fetch_attachment(self, folder_path: str, uid: str, attachment_index: int | str) -> AttachmentContent:
        url = f"{GRAPH_API_ROOT}/{self._resource_path}/messages/{uid}/attachments"
        response = self._session.get(url, headers=self._headers())
        response.raise_for_status()
        attachments = response.json().get("value", [])
        if isinstance(attachment_index, str):
            attachment = next((att for att in attachments if att["id"] == attachment_index), None)
        else:
            if attachment_index >= len(attachments):
                attachment = None
            else:
                attachment = attachments[attachment_index]
        if not attachment:
            raise AttachmentNotFoundError(f"Attachment {attachment_index} not found for message {uid}")
        attachment_id = attachment["id"]
        detail_url = f"{url}/{attachment_id}"
        attachment_response = self._session.get(detail_url, headers=self._headers())
        attachment_response.raise_for_status()
        attachment_payload = attachment_response.json()
        content_bytes = attachment_payload.get("contentBytes")
        download_url = attachment_payload.get("@microsoft.graph.downloadUrl")
        data = base64.b64decode(content_bytes) if content_bytes else b""
        metadata = AttachmentMetadata(
            attachment_id=attachment_id,
            filename=attachment_payload.get("name") or "attachment",
            content_type=attachment_payload.get("contentType", "application/octet-stream"),
            size=attachment_payload.get("size"),
            resource_uri=f"mail+attachment://{encode_folder_path(folder_path)}/{uid}/{attachment_id}",
        )
        return AttachmentContent(
            metadata=metadata,
            data=data,
            mime_type=metadata.content_type,
            file_name=metadata.filename,
            download_url=download_url,
        )

    # Internal helpers -------------------------------------------------

    def _build_app(self):
        oauth = self.config.oauth
        assert oauth is not None  # checked in __init__
        authority = oauth.authority
        if not authority and oauth.tenant_id:
            authority = f"https://login.microsoftonline.com/{oauth.tenant_id}"
        if not authority:
            raise ConnectorNotAvailableError(
                "OAuth authority must be provided for Microsoft Graph authentication."
            )
        return self._msal.ConfidentialClientApplication(
            client_id=oauth.client_id,
            client_credential=oauth.client_secret.get_secret_value() if oauth.client_secret else None,
            authority=authority,
        )

    def _headers(self, *, consistency: bool = False) -> dict[str, str]:
        token = self._ensure_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if consistency:
            headers["ConsistencyLevel"] = "eventual"
        return headers

    def _ensure_token(self) -> str:
        now = time.time()
        if self._token and now - self._token_acquired_at < self._token.get("expires_in", 300) - 60:
            return self._token["access_token"]
        oauth = self.config.oauth
        assert oauth is not None
        scopes = oauth.scopes or ["https://graph.microsoft.com/.default"]
        token = self._cca.acquire_token_silent(scopes, account=None)
        if not token:
            token = self._cca.acquire_token_for_client(scopes=scopes)
        if "access_token" not in token:
            raise ConnectorNotAvailableError(
                f"Unable to obtain Microsoft Graph access token: {token.get('error')}"
            )
        self._token = token
        self._token_acquired_at = now
        return token["access_token"]

    def _convert_message_summary(
        self, payload: dict[str, Any], fallback_folder: str | None
    ) -> MessageSummary:
        folder_id = payload.get("parentFolderId") or fallback_folder or "inbox"
        folder_token = encode_folder_path(folder_id)
        message_id = payload["id"]
        summary = MessageSummary(
            folder_path=folder_id,
            folder_token=folder_token,
            uid=message_id,
            subject=payload.get("subject"),
            **{
                "from": parse_address_list(_extract_address(payload.get("from"))),
            },
            to=_extract_addresses(payload.get("toRecipients")),
            cc=_extract_addresses(payload.get("ccRecipients")),
            bcc=_extract_addresses(payload.get("bccRecipients")),
            reply_to=_extract_addresses(payload.get("replyTo")),
            date=_parse_graph_datetime(payload.get("receivedDateTime") or payload.get("sentDateTime")),
            size=None,
            snippet=payload.get("bodyPreview"),
            has_attachments=payload.get("hasAttachments", False),
            flags=MessageFlags(
                seen=payload.get("isRead", True),
                draft=payload.get("isDraft", False),
                flagged=False,
                answered=False,
                recent=False,
                other=[],
            ),
            resource_uri=f"mail://{folder_token}/{message_id}",
            raw_resource_uri=f"mail+raw://{folder_token}/{message_id}",
        )
        return summary


def _build_resource_path(config: MailAccountConfig) -> str:
    oauth = config.oauth
    assert oauth is not None
    if oauth.user_id:
        return f"users/{oauth.user_id}"
    return "me"


def _build_messages_url(base: str, resource_path: str, folder: str | None) -> str:
    if folder:
        return f"{base}/{resource_path}/mailFolders/{folder}/messages"
    return f"{base}/{resource_path}/messages"


def _build_query_params(filters: MessageSearchFilters) -> dict[str, str]:
    params: dict[str, str] = {
        "$top": str(min(filters.limit or 20, 200)),
        "$orderby": "receivedDateTime desc",
        "$select": ",".join(
            [
                "id",
                "subject",
                "bodyPreview",
                "from",
                "toRecipients",
                "ccRecipients",
                "bccRecipients",
                "replyTo",
                "receivedDateTime",
                "sentDateTime",
                "hasAttachments",
                "parentFolderId",
                "isRead",
                "isDraft",
            ]
        ),
    }

    search_terms: list[str] = []
    if filters.text:
        search_terms.append(filters.text)
    if filters.sender:
        search_terms.append(f"from:{filters.sender}")
    if filters.recipient:
        search_terms.append(f"to:{filters.recipient}")
    if search_terms:
        joined = " ".join(search_terms)
        params["$search"] = f'"{joined}"'

    filter_clauses: list[str] = []
    if filters.has_attachments:
        filter_clauses.append("hasAttachments eq true")
    if filters.since:
        filter_clauses.append(f"receivedDateTime ge {filters.since.isoformat()}")
    if filters.until:
        filter_clauses.append(f"receivedDateTime le {filters.until.isoformat()}")
    if filter_clauses:
        params["$filter"] = " and ".join(filter_clauses)

    if filters.offset:
        params["$skip"] = str(filters.offset)

    return params


def _extract_addresses(items: list[dict[str, Any]] | None) -> list:
    addresses = []
    if not items:
        return []
    for item in items:
        addr = _extract_address(item)
        addresses.extend(parse_address_list(addr))
    return addresses


def _extract_address(container: dict[str, Any] | None) -> str | None:
    if not container:
        return None
    email_address = container.get("emailAddress") or container
    address = email_address.get("address")
    name = email_address.get("name")
    if name:
        return f"{name} <{address}>"
    return address


def _parse_graph_datetime(value: str | None):
    from dateutil import parser

    if not value:
        return None
    try:
        return parser.isoparse(value)
    except Exception:
        return None


def _infer_folder_role(display_name: str) -> MailboxRole:
    lowered = display_name.lower()
    if lowered == "inbox":
        return MailboxRole.INBOX
    if "sent" in lowered:
        return MailboxRole.SENT
    if "draft" in lowered:
        return MailboxRole.DRAFTS
    if "junk" in lowered or "spam" in lowered:
        return MailboxRole.JUNK
    if "trash" in lowered or "deleted" in lowered:
        return MailboxRole.TRASH
    if "archive" in lowered:
        return MailboxRole.ARCHIVE
    return MailboxRole.CUSTOM
