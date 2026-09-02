"""用量日志管理：服务端分页 + 过滤（基于 usage_logs 表，由代理网关写入）。"""
import csv
import io
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from admin.db import get_db
from admin.models import Account, ApiKey, UsageLog
from admin.security import require_admin

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
def list_logs(
    page: int = 1,
    page_size: int = 20,
    key_id: Optional[int] = None,
    account_id: Optional[int] = None,
    model: Optional[str] = None,
    key: Optional[str] = None,      # 按 Key 名称（模糊）筛选
    account: Optional[str] = None,  # 按账号名称 / UID（模糊）筛选
    client_ip: Optional[str] = None,
    start: Optional[str] = None,  # 起始时间 YYYY-MM-DD HH:MM:SS
    end: Optional[str] = None,
    _: bool = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(UsageLog)
    if key_id:
        q = q.filter(UsageLog.api_key_id == key_id)
    if account_id:
        q = q.filter(UsageLog.account_id == account_id)
    if model:
        q = q.filter(UsageLog.model.like(f"%{model}%"))
    if key:
        kid = db.query(ApiKey.id).filter(ApiKey.name.like(f"%{key}%")).scalar()
        if kid:
            q = q.filter(UsageLog.api_key_id == kid)
    if account:
        aid = db.query(Account.id).filter(
            (Account.name.like(f"%{account}%")) | (Account.uid.like(f"%{account}%"))
        ).scalar()
        if aid:
            q = q.filter(UsageLog.account_id == aid)
    if client_ip:
        q = q.filter(UsageLog.client_ip.like(f"%{client_ip}%"))
    if start:
        q = q.filter(UsageLog.created_at >= start)
    if end:
        q = q.filter(UsageLog.created_at <= end)

    total = q.count()
    rows = (
        q.order_by(UsageLog.id.desc())
        .offset((max(1, page) - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # 取名称映射，避免 N+1
    key_names = {k.id: k.name for k in db.query(ApiKey).all()}
    acc_names = {a.id: a.name for a in db.query(Account).all()}

    items = [
        {
            "id": r.id,
            "key_name": key_names.get(r.api_key_id) or f"#{r.api_key_id}",
            "account_name": acc_names.get(r.account_id) or f"#{r.account_id}",
            "model": r.model,
            "credits": r.credits,
            "prompt_tokens": r.prompt_tokens,
            "completion_tokens": r.completion_tokens,
            "total_tokens": r.total_tokens,
            "cached_tokens": r.cached_tokens,
            "client_ip": r.client_ip or "",
            "use_case": r.use_case or "",
            "seq": r.seq,
            "ttfb_ms": r.ttfb_ms,
            "latency_ms": r.latency_ms,
            "error_kind": r.error_kind or "",
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/export")
def export_logs(
    model: Optional[str] = None,
    key: Optional[str] = None,
    account: Optional[str] = None,
    client_ip: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    _: bool = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """导出用量日志为 CSV（UTF-8 BOM，Excel 直接可打开）。"""
    q = db.query(UsageLog)
    if model:
        q = q.filter(UsageLog.model.like(f"%{model}%"))
    if key:
        kid = db.query(ApiKey.id).filter(ApiKey.name.like(f"%{key}%")).scalar()
        if kid:
            q = q.filter(UsageLog.api_key_id == kid)
    if account:
        aid = db.query(Account.id).filter(
            (Account.name.like(f"%{account}%")) | (Account.uid.like(f"%{account}%"))
        ).scalar()
        if aid:
            q = q.filter(UsageLog.account_id == aid)
    if client_ip:
        q = q.filter(UsageLog.client_ip.like(f"%{client_ip}%"))
    if start:
        q = q.filter(UsageLog.created_at >= start)
    if end:
        q = q.filter(UsageLog.created_at <= end)
    rows = q.order_by(UsageLog.id.desc()).all()

    key_names = {k.id: k.name for k in db.query(ApiKey).all()}
    acc_names = {a.id: a.name for a in db.query(Account).all()}

    buf = io.StringIO()
    buf.write("﻿")  # UTF-8 BOM，保证 Excel 正确识别中文
    w = csv.writer(buf)
    w.writerow(["ID", "Key", "账号", "模型", "积分", "提示tokens", "补全tokens", "缓存tokens", "总tokens",
                "TTFB(ms)", "总耗时(ms)", "结果", "客户端IP", "用途", "时间(北京)"])
    for r in rows:
        t = r.created_at
        t_str = ""
        if t:
            # 数据库存 UTC，导出统一 +8 北京时间，与界面显示一致
            t_str = (t + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        w.writerow([
            r.id,
            key_names.get(r.api_key_id) or f"#{r.api_key_id}",
            acc_names.get(r.account_id) or f"#{r.account_id}",
            r.model,
            r.credits,
            r.prompt_tokens if r.prompt_tokens is not None else "",
            r.completion_tokens if r.completion_tokens is not None else "",
            r.cached_tokens if r.cached_tokens is not None else "",
            r.total_tokens if r.total_tokens is not None else "",
            r.ttfb_ms if r.ttfb_ms is not None else "",
            r.latency_ms if r.latency_ms is not None else "",
            r.error_kind or "",
            r.client_ip or "",
            r.use_case or "",
            t_str,
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=usage_logs.csv"},
    )
