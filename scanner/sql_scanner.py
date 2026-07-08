from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import requests
from utils.helpers import normalize_url
SQL_ERROR_PATTERNS = ['SQL syntax.*MySQL', 'Warning.*mysql_', 'PostgreSQL.*ERROR', 'valid PostgreSQL result', 'Microsoft OLE DB Provider', 'ODBC SQL Server Driver', 'SQLite/JDBCDriver', 'sqlite3\\.OperationalError', 'ORA-\\d{5}', 'unterminated quoted string', 'you have an error in your sql syntax']
SAFE_SQL_PAYLOADS = ["'", '"', "'--", '")', "' OR '1'='1"]

@dataclass
class SQLInjectionScanner:
    timeout: int = 10
    session: requests.Session = field(default_factory=requests.Session)

    def scan(self, url: str) -> list[dict[str, Any]]:
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return [{'parameter': 'N/A', 'payload': 'N/A', 'vulnerable': False, 'evidence': 'No query parameters found to test safely.', 'severity': 'Low'}]
        findings: list[dict[str, Any]] = []
        baseline_text = self._safe_get_text(normalized_url)
        for param_name, original_value in params:
            for payload in SAFE_SQL_PAYLOADS:
                test_params = [(name, f'{value}{payload}' if name == param_name else value) for name, value in params]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                response_text = self._safe_get_text(test_url)
                evidence = self._find_sql_error(response_text)
                response_difference = abs(len(response_text) - len(baseline_text))
                vulnerable = bool(evidence) or response_difference > max(800, len(baseline_text) * 0.35)
                findings.append({'parameter': param_name, 'original_value': original_value, 'payload': payload, 'vulnerable': vulnerable, 'evidence': evidence or f'Response length difference: {response_difference} characters', 'severity': 'High' if vulnerable else 'Low'})
        return findings

    def _safe_get_text(self, url: str) -> str:
        try:
            response = self.session.get(url, timeout=self.timeout)
            return response.text[:200000]
        except requests.RequestException:
            return 'REQUEST_ERROR'

    @staticmethod
    def _find_sql_error(text: str) -> str:
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f'SQL error indicator matched: {match.group(0)}'
        return ''