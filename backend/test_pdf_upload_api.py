import io
import os
import unittest
import uuid
from unittest.mock import patch

from pypdf import PdfWriter

from backend.app import app
from backend.authentication import create_access_token

ENDPOINT = "/api/cti/extract-pdf"
EXTRACTOR = "backend.advanced_cti.extract_cti_from_pdf"
MAX_PDF_BYTES = 15 * 1024 * 1024  # the route's 15 MiB PDF limit


def build_multipart_body(content, filename, field="file"):
    """
    Return (body bytes, Content-Type header) for a one-file multipart upload.

    Passing a ready-made bytes body to the test client avoids Werkzeug's
    multipart encoder, which spills large payloads into a TemporaryFile that
    the test client never closes (this caused a ResourceWarning).
    """
    boundary = "ctitest" + uuid.uuid4().hex
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\n'
        "Content-Type: application/pdf\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()

    return head + content + tail, f"multipart/form-data; boundary={boundary}"


class PDFUploadAPITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()
        cls.token = create_access_token(1)

        writer = PdfWriter()
        writer.add_blank_page(width=300, height=300)

        pdf_buffer = io.BytesIO()
        writer.write(pdf_buffer)
        cls.blank_pdf = pdf_buffer.getvalue()

    # ------------------------------------------------------
    # Helpers
    # ------------------------------------------------------

    def auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def post_pdf(self, content, filename, headers=None):
        """Upload `content` as a multipart file named `filename`."""
        return self.client.post(
            ENDPOINT,
            data={"file": (io.BytesIO(content), filename)},
            headers=self.auth_headers() if headers is None else headers,
            content_type="multipart/form-data",
        )

    def post_pdf_raw(self, content, filename, headers=None):
        """
        Upload `content` using a hand-built multipart body.

        Same request as post_pdf, but without Werkzeug's multipart encoder,
        so large payloads do not leave an unclosed temporary file behind.
        """
        body, content_type = build_multipart_body(content, filename)

        return self.client.post(
            ENDPOINT,
            data=body,
            headers=self.auth_headers() if headers is None else headers,
            content_type=content_type,
        )

    # ------------------------------------------------------
    # Authentication
    # ------------------------------------------------------

    def test_requires_authentication(self):
        response = self.client.post(ENDPOINT)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json()["error"],
            "Authentication required",
        )

    def test_rejects_invalid_token(self):
        response = self.post_pdf(
            self.blank_pdf,
            "report.pdf",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------
    # Input validation
    # ------------------------------------------------------

    def test_rejects_missing_file(self):
        response = self.client.post(
            ENDPOINT,
            headers=self.auth_headers(),
        )

        self.assertEqual(response.status_code, 400)

    def test_rejects_non_pdf_filename(self):
        response = self.post_pdf(b"not a pdf", "report.txt")

        self.assertEqual(response.status_code, 400)

    def test_rejects_invalid_pdf_content(self):
        response = self.post_pdf(b"this is not a PDF", "report.pdf")

        self.assertEqual(response.status_code, 400)

    def test_rejects_pdf_larger_than_route_limit(self):
        # The route checks the limit while streaming the upload, so a
        # payload just over 15 MiB must be refused before extraction.
        # The multipart body is built by hand (see build_multipart_body)
        # so the test client does not open an unclosed temporary file.
        large_content = b"%PDF-" + b"A" * (MAX_PDF_BYTES + 1024)

        with patch(EXTRACTOR) as mocked_extractor:
            response = self.post_pdf_raw(large_content, "large-report.pdf")

        self.assertEqual(response.status_code, 413)
        mocked_extractor.assert_not_called()

    def test_hand_built_multipart_body_is_accepted_by_route(self):
        # Guards the oversized-upload test: if the helper produced a body
        # the route could not parse, the 413 test above could pass or fail
        # for the wrong reason. A small valid upload must succeed.
        extraction = {
            "page_count": 1,
            "pages_with_text": 1,
            "findings": [{
                "type": "cve",
                "value": "CVE-2024-12345",
                "page": 1,
                "evidence": "Example evidence for testing",
                "method": "regex_rule",
                "review_status": "unreviewed",
            }],
            "limitations": [],
        }

        with patch(EXTRACTOR, return_value=extraction):
            response = self.post_pdf_raw(self.blank_pdf, "raw-report.pdf")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["filename"], "raw-report.pdf")

    # ------------------------------------------------------
    # Successful extraction
    # ------------------------------------------------------

    @patch(
        EXTRACTOR,
        return_value={
            "page_count": 1,
            "pages_with_text": 1,
            "findings": [{
                "type": "cve",
                "value": "CVE-2024-12345",
                "page": 1,
                "evidence": "Example evidence for testing",
                "method": "regex_rule",
                "review_status": "unreviewed",
            }],
            "limitations": [],
        },
    )
    def test_valid_pdf_returns_preview_without_saving(
        self,
        mocked_extractor,
    ):
        response = self.post_pdf(self.blank_pdf, "test-report.pdf")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["organization_id"], 1)
        self.assertEqual(data["filename"], "test-report.pdf")
        self.assertFalse(data["saved_to_database"])

        findings = data["extraction"]["findings"]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["value"], "CVE-2024-12345")
        self.assertEqual(findings[0]["page"], 1)
        self.assertEqual(findings[0]["review_status"], "unreviewed")
        self.assertIn("evidence", findings[0])

        mocked_extractor.assert_called_once()

    # ------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------

    def test_temporary_file_is_removed_after_extraction(self):
        # Save the real function before mocking os.remove.
        real_remove = os.remove
        removed_paths = []

        def record_remove(path):
            removed_paths.append(path)
            real_remove(path)

        with patch(
            EXTRACTOR,
            side_effect=ValueError("Test extraction error"),
        ), patch(
            "backend.advanced_cti.os.remove",
            side_effect=record_remove,
        ):
            response = self.post_pdf(self.blank_pdf, "test-report.pdf")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(removed_paths), 1)
        self.assertFalse(os.path.exists(removed_paths[0]))


if __name__ == "__main__":
    unittest.main()