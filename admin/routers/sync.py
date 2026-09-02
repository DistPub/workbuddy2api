"""线上同步：把本地账号 / 模型配置推送到线上数据库。

设计：
  - 本地数据视为最新（source of truth）。
  - 在「系统设置」里配置 远程 URL + 密钥（HMAC 签名用）。
  - 点「同步到线上」→ 把本地 accounts + model_configs 推送过去。
  - 同一个服务也可作为「线上实例」接收数据（/api/sync/receive），
    只要线上实例配置了相同的 密钥 即可校验并写入自己的库。
"""
import hashlib
import hmac
import json
import platform
import socket
import time
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from admin.db import get_db
from admin.models import Account, ModelConfig, SystemSetting
from admin.security import require_admin

router = APIRouter(prefix="/api/sync", tags=["sync"])

_K_URL = "sync_remote_url"
_K_SECRET = "sync_secret"


def _generate_device_secret() -> str:
    """基于本机特征生成唯一密钥（同机器每次调用结果相同，不同机器几乎必然不同）。"""
    raw = f"{socket.gethostname()}-{platform.machine()}-{platform.processor() or ''}-{uuid.getnode()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]  # 取前 32 位作为可读密钥


class SyncConfigIn(BaseModel):
    remote_url: str = ""
    secret: str = ""


def _get_setting(db: Session, key: str) -> str:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if row else ""


def _set_setting(db: Session, key: str, value: str):
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))
    db.commit()


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@router.get("/config")
def get_config(_: bool = Depends(require_admin), db: Session = Depends(get_db)):
    secret = _get_setting(db, _K_SECRET)
    # 首次访问且未配置时自动生成基于设备的唯一密钥
    is_auto = False
    if not secret:
        secret = _generate_device_secret()
        _set_setting(db, _K_SECRET, secret)
        is_auto = True
    return {
        "remote_url": _get_setting(db, _K_URL),
        "secret": secret,  # 前端可展示完整密钥（仅已登录管理员可见）
        "secret_masked": ("*" * 8 + secret[-4:]) if len(secret) > 4 else ("****" if secret else ""),
        "is_auto_generated": is_auto,  # 本次是否为自动生成
    }


@router.post("/config")
def save_config(body: SyncConfigIn, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    if body.remote_url:
        _set_setting(db, _K_URL, body.remote_url.rstrip("/"))
    # 密钥：用户未填写时自动生成设备唯一密钥
    secret = body.secret.strip() if body.secret and body.secret.strip() else (_get_setting(db, _K_SECRET) or _generate_device_secret())
    if secret:
        _set_setting(db, _K_SECRET, secret)
    return {"ok": True, "secret_set": bool(secret)}


@router.post("/push")
def push(
    body: SyncConfigIn | None = None,
    _: bool = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """把本地账号/模型配置推送到线上。

    支持两种调用方式：
      1. 客户端调用前已先调用 /api/sync/config 保存过——这里直接读 DB。
      2. 客户端把当前输入框的 remote_url/secret 通过 body 一起带上——
         服务端会先写入 DB 再推送，这样前端不必强制先「保存配置」。

    这样无论用户是否记得点「保存配置」，只要输入框里有值就能直接推送。
    """
    # 优先用请求体里的值（避免前端遗漏保存步骤），再回退到 DB
    incoming_url = (body.remote_url or "").strip() if body else ""
    incoming_secret = (body.secret or "").strip() if body else ""
    if incoming_url:
        _set_setting(db, _K_URL, incoming_url.rstrip("/"))
    if incoming_secret:
        _set_setting(db, _K_SECRET, incoming_secret)

    remote_url = _get_setting(db, _K_URL)
    secret = _get_setting(db, _K_SECRET)
    if not remote_url or not secret:
        raise HTTPException(
            status_code=400,
            detail="请先在「同步设置」中填写并保存 远程 URL 与 密钥",
        )

    accounts = []
    for a in db.query(Account).all():
        accounts.append({
            "uid": a.uid,
            "name": a.name,
            "enterprise_id": a.enterprise_id,
            "domain": a.domain,
            "status": a.status,
            "auth_json": a.auth_json,
            "balance_total": a.balance_total,
            "balance_remain": a.balance_remain,
        })
    models = []
    for m in db.query(ModelConfig).all():
        models.append({
            "level": m.level,
            "model_id": m.model_id,
            "enabled": m.enabled,
            "credit_multiplier": m.credit_multiplier or 0,
            "credits_raw": m.credits_raw or "",
            "note": m.note or "",
        })

    payload = {
        "source": "workbuddy2api-admin",
        "pushed_at": int(time.time()),
        "accounts": accounts,
        "models": models,
    }
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sig = _sign(secret, raw)

    target = f"{remote_url}/api/sync/receive"
    try:
        with httpx.Client(timeout=30) as client:
            r = client.post(target, content=raw, headers={
                "Content-Type": "application/json",
                "X-Sync-Signature": sig,
            })
            if r.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"线上返回错误 {r.status_code}: {r.text[:300]}")
            resp = r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"推送失败: {e}")

    return {"ok": True, "remote": remote_url, "accounts": len(accounts), "models": len(models), "remote_result": resp}


@router.post("/receive")
async def receive(request: Request, db: Session = Depends(get_db)):
    """线上实例接收端：校验签名后 upsert 账号与模型配置。

    用本实例 system_settings 里的 sync_secret 校验（线上实例需配置相同密钥）。
    """
    secret = _get_setting(db, _K_SECRET)
    if not secret:
        raise HTTPException(status_code=400, detail="线上实例未配置同步密钥，无法接收")
    raw = await request.body()
    sig = request.headers.get("X-Sync-Signature", "")
    expected = _sign(secret, raw)
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="签名校验失败")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="无效 JSON")

    acc_added = acc_updated = 0
    for a in payload.get("accounts", []):
        uid = a.get("uid")
        if not uid or not a.get("auth_json"):
            continue
        existing = db.query(Account).filter(Account.uid == uid).first()
        if existing:
            existing.auth_json = a["auth_json"]
            existing.name = a.get("name") or existing.name
            existing.enterprise_id = a.get("enterprise_id") or ""
            existing.domain = a.get("domain") or ""
            existing.status = a.get("status") or "active"
            existing.balance_total = int(a.get("balance_total") or 0)
            existing.balance_remain = int(a.get("balance_remain") or 0)
            acc_updated += 1
        else:
            db.add(Account(
                name=a.get("name") or "",
                uid=uid,
                enterprise_id=a.get("enterprise_id") or "",
                domain=a.get("domain") or "",
                status=a.get("status") or "active",
                auth_json=a["auth_json"],
                balance_total=int(a.get("balance_total") or 0),
                balance_remain=int(a.get("balance_remain") or 0),
            ))
            acc_added += 1

    model_added = model_updated = 0
    for m in payload.get("models", []):
        mid = m.get("model_id")
        if not mid:
            continue
        existing = db.query(ModelConfig).filter(ModelConfig.model_id == mid).first()
        if existing:
            existing.enabled = int(m.get("enabled", existing.enabled))
            existing.credit_multiplier = float(m.get("credit_multiplier", existing.credit_multiplier or 0))
            existing.credits_raw = m.get("credits_raw") or ""
            existing.note = m.get("note") or existing.note
            model_updated += 1
        else:
            db.add(ModelConfig(
                level=m.get("level") or "system",
                model_id=mid,
                enabled=int(m.get("enabled", 1)),
                credit_multiplier=float(m.get("credit_multiplier", 0) or 0),
                credits_raw=m.get("credits_raw") or "",
                note=m.get("note") or "",
            ))
            model_added += 1

    db.commit()
    return {
        "ok": True,
        "accounts": {"added": acc_added, "updated": acc_updated},
        "models": {"added": model_added, "updated": model_updated},
    }
