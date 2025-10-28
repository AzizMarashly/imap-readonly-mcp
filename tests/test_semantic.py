from imap_readonly_mcp.models import MessageBody, MessageDetail, MessageFlags
from imap_readonly_mcp.semantic.index import SemanticIndexer
from imap_readonly_mcp.utils.identifiers import encode_folder_path


def build_detail(uid: str, text: str) -> MessageDetail:
    folder = "INBOX"
    summary_data = {
        "account_id": "acc",
        "folder_path": folder,
        "folder_token": encode_folder_path(folder),
        "uid": uid,
        "subject": "Subject",
        "from_": [],
        "to": [],
        "cc": [],
        "bcc": [],
        "reply_to": [],
        "date": None,
        "size": None,
        "snippet": text,
        "has_attachments": False,
        "flags": MessageFlags(),
        "resource_uri": f"mail://acc/{encode_folder_path(folder)}/{uid}",
        "raw_resource_uri": f"mail+raw://acc/{encode_folder_path(folder)}/{uid}",
    }
    return MessageDetail(
        **summary_data,
        body=MessageBody(text=text, html=None, charset="utf-8"),
        attachments=[],
        headers={},
        raw_source=None,
    )


def test_semantic_indexer_lexical_fallback():
    indexer = SemanticIndexer(enabled=True, model_name=None)
    indexer.add_message(build_detail("1", "Bonjour le monde"), account_id="acc")
    matches = indexer.search(account_id="acc", folder_token=None, query="Bonjour", top_k=3)
    assert matches
    assert matches[0].summary.uid == "1"
