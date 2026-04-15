"""Yahoo 邮箱导入规则：解析、验证"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass


@dataclass
class YahooMailImportRecord:
    line_number: int
    email: str
    app_password: str = ""
    session_data: str = ""


class YahooRowParser:
    """解析 Yahoo 邮箱导入行

    支持格式：
    - email----app_password----session_json_base64
    - email----app_password（session 后续补充）
    """

    def parse(self, line_number: int, line: str) -> YahooMailImportRecord:
        parts = [p.strip() for p in str(line or "").split("----")]
        if len(parts) < 2:
            raise ValueError(
                f"行 {line_number}: 格式错误，至少需要 邮箱----应用专用密码"
            )

        email = parts[0]
        if "@" not in email:
            raise ValueError(f"行 {line_number}: 邮箱格式无效: {email}")

        app_password = parts[1]
        if not app_password:
            raise ValueError(f"行 {line_number}: 应用专用密码不能为空")

        session_data = ""
        if len(parts) >= 3 and parts[2]:
            raw = parts[2]
            # 尝试 base64 解码
            try:
                decoded = base64.b64decode(raw).decode("utf-8")
                payload = json.loads(decoded)
                if isinstance(payload, dict):
                    session_data = decoded
            except Exception:
                pass
            # 如果不是 base64，尝试直接作为 JSON
            if not session_data:
                try:
                    payload = json.loads(raw)
                    if isinstance(payload, dict):
                        session_data = raw
                except (json.JSONDecodeError, TypeError):
                    raise ValueError(
                        f"行 {line_number}: session 数据格式无效，需要 base64 编码的 JSON 或直接 JSON"
                    )

        return YahooMailImportRecord(
            line_number=line_number,
            email=email,
            app_password=app_password,
            session_data=session_data,
        )


class DuplicateYahooMailboxRule:
    """检查邮箱是否已存在"""

    def evaluate(self, record: YahooMailImportRecord, context: dict) -> dict:
        existing = context.get("existing_emails", set())
        if record.email in existing:
            return {
                "ok": False,
                "message": f"行 {record.line_number}: Yahoo 邮箱已存在: {record.email}",
            }
        return {"ok": True, "message": "ok"}


class SessionDataRule:
    """检查 session 数据的有效性"""

    def evaluate(self, record: YahooMailImportRecord, context: dict) -> dict:
        if not record.session_data:
            # session 可以后续补充，不强制要求
            return {"ok": True, "message": "ok"}
        try:
            payload = json.loads(record.session_data)
            if not isinstance(payload, dict):
                return {
                    "ok": False,
                    "message": f"行 {record.line_number}: session 数据必须是 JSON 对象",
                }
            if not payload.get("wssid"):
                return {
                    "ok": False,
                    "message": f"行 {record.line_number}: session 数据缺少 wssid 字段",
                }
            if not payload.get("mailbox_id"):
                return {
                    "ok": False,
                    "message": f"行 {record.line_number}: session 数据缺少 mailbox_id 字段",
                }
        except (json.JSONDecodeError, TypeError):
            return {
                "ok": False,
                "message": f"行 {record.line_number}: session 数据不是有效 JSON",
            }
        return {"ok": True, "message": "ok"}


class YahooMailImportRuleEngine:
    def __init__(self, rules=None):
        self._rules = rules or [
            DuplicateYahooMailboxRule(),
            SessionDataRule(),
        ]

    def evaluate(self, record: YahooMailImportRecord, context: dict) -> dict:
        for rule in self._rules:
            result = rule.evaluate(record, context)
            if not result.get("ok"):
                return result
        return {"ok": True, "message": "ok"}
