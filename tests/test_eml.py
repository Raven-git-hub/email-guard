"""Raw .eml round-trip: parse -> clean -> verdict, all through the stdlib."""

from __future__ import annotations

from email.message import EmailMessage

from email_guard import parse
from email_guard.clean import clean, pick_source
from email_guard.clean import gmail, outlook, proton
from email_guard.clean.common import normalise
from email_guard.pipeline import scan_parsed


def test_eml_fixture_round_trips(scan):
    verdict = scan("eml/simple.eml")

    assert verdict["message_id"] == "<plain-0001@unknown-sender.example>"
    assert verdict["sender"] == "sam@unknown-sender.example"
    assert verdict["greylist_classification"] == "none"
    assert verdict["proposal"]["classification"] == "unknown_domain"
    assert verdict["bucket"] in {"rejected", "flagged", "cleared"}

    # The link is extracted from the HTML part and de-fanged.
    assert verdict["links"] == ["h_ttps://notes[.]unknown-sender[.]example/thursday"]


def test_eml_parses_headers_body_and_attachment():
    message = EmailMessage()
    message["From"] = '"Sam Example" <sam@unknown-sender.example>'
    message["To"] = "owner@example.com"
    message["Subject"] = "Fwd: Quarterly figures"
    message["Message-ID"] = "<att-0001@example.com>"
    message.set_content("Plain body")
    message.add_alternative("<html><body><p>Rich body</p></body></html>", subtype="html")
    message.add_attachment(
        b"%PDF-1.4 fake",
        maintype="application",
        subtype="pdf",
        filename="figures.pdf",
    )

    parsed = parse.parse_eml(message.as_bytes())

    # Decoding normalises the display name's quoting; the address is intact.
    assert "<sam@unknown-sender.example>" in parsed["from"]
    assert "Sam Example" in parsed["from"]
    assert parsed["subject"] == "Fwd: Quarterly figures"
    assert "Rich body" in parsed["textHtml"]
    assert "Plain body" in parsed["textPlain"]
    assert parsed["attachments"] == [
        {"filename": "figures.pdf", "contentType": "application/pdf"}
    ]


def test_encoded_word_subject_is_decoded():
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: =?utf-8?q?Caf=C3=A9_meeting?=\r\n"
        b"\r\n"
        b"body\r\n"
    )
    assert parse.parse_eml(raw)["subject"] == "Café meeting"


def test_forwarding_prefix_is_stripped_from_the_title(lists):
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: Fwd: Quarterly figures\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"body\r\n"
    )
    message = clean(parse.parse_eml(raw), lists)
    assert message["title"] == "Quarterly figures"


def test_plain_text_only_message_still_yields_clean_text(lists):
    """The prototype read textHtml only; a plain message must not clean to nothing."""
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: Notes\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Some plain words here.\r\n"
    )
    message = clean(parse.parse_eml(raw), lists)
    assert "Some plain words here." in message["clean_text"]


def test_repeated_received_headers_become_a_hop_count(lists):
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: Notes\r\n"
        b"Received: from a.example.com by b.example.com\r\n"
        b"Received: from b.example.com by c.example.com\r\n"
        b"Received: from c.example.com by d.example.com\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse.parse_eml(raw)
    assert isinstance(parsed["metadata"]["received"], list)
    assert parse.hop_count(parsed["metadata"]["received"]) == 3


# --- source fingerprinting -----------------------------------------------------


def test_outlook_headers_pick_the_outlook_cleaner():
    assert pick_source({"metadata": {"x-ms-publictraffictype": "Email"}}) is outlook


def test_gmail_headers_pick_the_gmail_cleaner():
    assert pick_source({"metadata": {"x-gm-message-state": "abc"}}) is gmail
    assert pick_source({"metadata": {"x-google-dkim-signature": "v=1"}}) is gmail


def test_anything_else_falls_back_to_proton():
    assert pick_source({"metadata": {"subject": "hello"}}) is proton


def test_all_three_cleaners_emit_the_identical_shape(lists):
    """The contract fix: one normalised shape across every source."""
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: Notes\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse.parse_eml(raw)

    shapes = []
    for source in (outlook, gmail, proton):
        message = normalise(parsed, source, lists)
        shapes.append(
            (
                tuple(sorted(message)),
                tuple(sorted(message["metadata"])),
                tuple(
                    sorted(
                        (section, tuple(sorted(values)))
                        for section, values in message["metadata"].items()
                    )
                ),
                tuple(sorted(message["integrity"])),
                tuple(sorted(message["content"])),
            )
        )

    assert shapes[0] == shapes[1] == shapes[2]


def test_cli_json_output_matches_the_library(pack, lists, capsys):
    """The CLI is a thin wrapper: same verdict either way."""
    from email_guard.cli import main
    import json

    from tests.conftest import EML_FIXTURES, LIST_FIXTURES

    exit_code = main(
        [
            str(EML_FIXTURES / "simple.eml"),
            "--lists-dir",
            str(LIST_FIXTURES),
            "--job-id",
            "test-job",
        ]
    )
    assert exit_code == 0
    from_cli = json.loads(capsys.readouterr().out)

    parsed = parse.parse_eml_file(EML_FIXTURES / "simple.eml")
    from_library = scan_parsed(parsed, lists, pack, job_id="test-job")

    assert from_cli == from_library
