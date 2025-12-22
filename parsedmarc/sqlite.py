# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Any, Iterable, Sequence

import json
import os
import re
import sqlite3


class SQLiteStorageError(RuntimeError):
    """Raised when persisting reports to SQLite fails."""


class SQLiteClient:
    """Lightweight helper for writing parsed DMARC reports to SQLite."""

    _TABLE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def __init__(
        self,
        database_path: str,
        *,
        aggregate_table: str = "dmarc_aggregate",
        forensic_table: str = "dmarc_forensic",
        smtp_tls_table: str = "smtp_tls",
    ):
        if not database_path:
            raise SQLiteStorageError("database_path is required")

        self.database_path = os.path.expanduser(database_path)

        parent_directory = os.path.dirname(self.database_path)
        if parent_directory:
            os.makedirs(parent_directory, exist_ok=True)

        self.aggregate_table = self._validate_table_name(
            aggregate_table, "aggregate_table"
        )
        self.forensic_table = self._validate_table_name(
            forensic_table, "forensic_table"
        )
        self.smtp_tls_table = self._validate_table_name(
            smtp_tls_table, "smtp_tls_table"
        )

        try:
            self._connection = sqlite3.connect(self.database_path)
        except sqlite3.Error as exc:
            raise SQLiteStorageError(
                f"Unable to open SQLite database at {self.database_path}: {exc}"
            ) from exc

        self._initialize_database()

    def close(self):
        """Close the SQLite connection."""
        try:
            if getattr(self, "_connection", None):
                self._connection.close()
                self._connection = None
        except sqlite3.Error:
            pass

    def __del__(self):
        self.close()

    def save_aggregate_reports(
        self, reports: Iterable[dict[str, Any]] | dict[str, Any]
    ):
        """Persist aggregate DMARC reports."""
        self._save_reports(
            reports,
            table_name=self.aggregate_table,
            report_id_path=("report_metadata", "report_id"),
            org_path=("report_metadata", "org_name"),
        )

    def save_forensic_reports(
        self, reports: Iterable[dict[str, Any]] | dict[str, Any]
    ):
        """Persist forensic/failure DMARC reports."""
        self._save_reports(
            reports,
            table_name=self.forensic_table,
            report_id_path=("arrival_date",),
            org_path=("reported_domain",),
        )

    def save_smtp_tls_reports(
        self, reports: Iterable[dict[str, Any]] | dict[str, Any]
    ):
        """Persist SMTP TLS reports."""
        self._save_reports(
            reports,
            table_name=self.smtp_tls_table,
            report_id_path=("report_id",),
            org_path=("organization_name",),
        )

    def _initialize_database(self):
        self._connection.execute("PRAGMA journal_mode=WAL")

        for table_name in (
            self.aggregate_table,
            self.forensic_table,
            self.smtp_tls_table,
        ):
            self._ensure_table(table_name)

    def _ensure_table(self, table_name: str):
        ddl = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            report_org TEXT,
            report_json JSONB NOT NULL,
            inserted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
        index_report_id = (
            f"CREATE INDEX IF NOT EXISTS idx_{table_name}_report_id "
            f"ON {table_name}(report_id)"
        )
        index_report_org = (
            f"CREATE INDEX IF NOT EXISTS idx_{table_name}_report_org "
            f"ON {table_name}(report_org)"
        )
        index_policy_domain = (
            f"""
            CREATE INDEX IF NOT EXISTS idx_{table_name}_policy_domain
            ON {table_name}(
                json_extract(report_json, '$.policy_published.domain')
            )
            """
        )
        index_inserted_at = (
            f"CREATE INDEX IF NOT EXISTS idx_{table_name}_inserted_at "
            f"ON {table_name}(inserted_at)"
        )
        index_begin_date = (
            f"""
            CREATE INDEX IF NOT EXISTS idx_{table_name}_begin_date
            ON {table_name}(
                json_extract(report_json, '$.report_metadata.begin_date')
            )
            """
        )
        index_end_date = (
            f"""
            CREATE INDEX IF NOT EXISTS idx_{table_name}_end_date
            ON {table_name}(
                json_extract(report_json, '$.report_metadata.end_date')
            )
            """
        )

        try:
            self._connection.execute(ddl)
            self._connection.execute(index_report_id)
            self._connection.execute(index_report_org)
            self._connection.execute(index_policy_domain)
            self._connection.execute(index_inserted_at)
            self._connection.execute(index_begin_date)
            self._connection.execute(index_end_date)
            self._connection.commit()
        except sqlite3.Error as exc:
            raise SQLiteStorageError(
                f"Failed to initialize table {table_name}: {exc}"
            ) from exc

    def _save_reports(
        self,
        reports: Iterable[dict[str, Any]] | dict[str, Any] | None,
        *,
        table_name: str,
        report_id_path: Sequence[str] | None,
        org_path: Sequence[str] | None,
    ):
        normalized = self._normalize_reports(reports)
        if not normalized:
            return

        payload = []
        for report in normalized:
            payload.append(
                (
                    self._get_nested_value(report, report_id_path),
                    self._get_nested_value(report, org_path),
                    self._serialize(report),
                )
            )

        try:
            self._connection.executemany(
                f"INSERT INTO {table_name} "
                "(report_id, report_org, report_json) VALUES (?, ?, ?)",
                payload,
            )
            self._connection.commit()
        except sqlite3.Error as exc:
            raise SQLiteStorageError(
                f"SQLite error while saving reports to {table_name}: {exc}"
            ) from exc

    @staticmethod
    def _normalize_reports(
        reports: Iterable[dict[str, Any]] | dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        if reports is None:
            return []
        if isinstance(reports, dict):
            return [reports]
        return [report for report in reports if report is not None]

    @staticmethod
    def _serialize(report: dict[str, Any]) -> str:
        return json.dumps(report, ensure_ascii=False, default=str)

    @staticmethod
    def _get_nested_value(
        report: dict[str, Any], path: Sequence[str] | None
    ) -> Any:
        if not path:
            return None
        value: Any = report
        for key in path:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
            if value is None:
                return None
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, default=str)
        return value

    def _validate_table_name(self, name: str, option_name: str) -> str:
        if not name:
            raise SQLiteStorageError(f"{option_name} cannot be empty")
        if not self._TABLE_NAME_PATTERN.match(name):
            raise SQLiteStorageError(
                f"{option_name} '{name}' is not a valid SQLite table name"
            )
        return name
