from imap_readonly_mcp.utils.identifiers import decode_folder_token, encode_folder_path


def test_folder_token_roundtrip():
    original = "INBOX/Subfolder/📬"
    token = encode_folder_path(original)
    assert token != original
    recovered = decode_folder_token(token)
    assert recovered == original
