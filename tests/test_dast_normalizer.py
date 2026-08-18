"""
Regression Tests for DAST Normalizer & Zero-Network Header Parser.
"""

import unittest
from unittest.mock import patch

from parsers.dast_normalizer import parse_zap_response_headers, normalize_dast_findings


class TestDASTNormalizer(unittest.TestCase):

    def test_parse_zap_response_headers_success(self):
        """Verify headers text is parsed in-memory with status 200 and security header detection."""
        raw_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "X-Powered-By: PHP/8.0.30\r\n"
            "Set-Cookie: PHPSESSID=abc123xyz; path=/\r\n"
        )
        res = parse_zap_response_headers(raw_headers)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["status_code"], "200")
        self.assertEqual(res["content_type"], "text/html; charset=UTF-8")
        self.assertEqual(res["x_powered_by"], "PHP/8.0.30")
        self.assertEqual(res["sec_headers"]["X-Content-Type-Options"], "[NOT PRESENT]")
        self.assertEqual(res["sec_headers"]["X-Frame-Options"], "[NOT PRESENT]")
        self.assertEqual(res["sec_headers"]["Content-Security-Policy"], "[NOT PRESENT]")

    def test_parse_zap_response_headers_zero_network_calls(self):
        """Verify zero network socket/requests calls are made during parsing."""
        raw_headers = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n"
        with patch("socket.socket") as mock_socket, patch("requests.get") as mock_get:
            res = parse_zap_response_headers(raw_headers)
            mock_socket.assert_not_called()
            mock_get.assert_not_called()
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["status_code"], "404")

    def test_parse_zap_response_headers_empty_handling(self):
        """Verify graceful failure dictionary returned for empty or invalid raw headers."""
        res_empty = parse_zap_response_headers("")
        self.assertEqual(res_empty["status"], "FAILED")
        res_none = parse_zap_response_headers(None)
        self.assertEqual(res_none["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
