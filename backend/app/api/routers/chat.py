"""
Chat Router — Updated to:
  - Decrypt content_encrypted on read (AES-256-GCM)
  - Return extended threat risk fields
  - Soft-fail decryption (return [ENCRYPTED] on failure)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional
from app.api import deps
from app.models.user import User
from app.models.message import Message
from app.services.encryption import decrypt_message
from pydantic import BaseModel
from datetime import datetime
import json
import logging

logger = logging.getLogger("chat_router")
router = APIRouter()


class MessageResponse(BaseModel):
    id: int
    text: str
    sender: str
    timestamp: datetime
    status: str
    risk: Optional[dict] = None
    file_url: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[str] = None
    integrity_hash: Optional[str] = None
    reply_to: Optional[dict] = None
    is_deleted: Optional[bool] = False

    class Config:
        from_attributes = True


class DMRequest(BaseModel):
    identifier: str  # Email or User ID


def _decrypt_safe(content: str) -> str:
    """Decrypt AES-256-GCM content. Returns original if decryption fails (backwards-compat)."""
    if not content:
        return ""
    try:
        return decrypt_message(content)
    except Exception:
        # Backwards compatibility: if not encrypted (old messages), return as-is
        return content


@router.post("/dm")
def start_dm(
    request: DMRequest,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    target_user = None
    if request.identifier.isdigit():
        target_user = db.query(User).filter(User.id == int(request.identifier)).first()
    if not target_user:
        target_user = db.query(User).filter(User.email == request.identifier).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    if target_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot DM yourself")

    u1 = min(current_user.id, target_user.id)
    u2 = max(current_user.id, target_user.id)
    channel_id = f"dm_{u1}_{u2}"

    return {
        "channel_id": channel_id,
        "target_user": {
            "id": target_user.id,
            "full_name": target_user.full_name,
            "email": target_user.email
        }
    }


@router.get("/dms")
def get_dms(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    sent_channels = (
        db.query(Message.channel_id)
        .filter(Message.sender_id == current_user.id)
        .filter(Message.channel_id.like("dm_%"))
        .distinct().all()
    )
    received_channels = (
        db.query(Message.channel_id)
        .filter(Message.receiver_id == current_user.id)
        .filter(Message.channel_id.like("dm_%"))
        .distinct().all()
    )

    all_channel_ids = set(c[0] for c in sent_channels)
    all_channel_ids.update(c[0] for c in received_channels)

    dms = []
    for cid in all_channel_ids:
        try:
            parts = cid.split("_")
            if len(parts) != 3:
                continue
            uid1, uid2 = int(parts[1]), int(parts[2])
            other_id = uid2 if uid1 == current_user.id else uid1
            if uid1 != current_user.id and uid2 != current_user.id:
                continue
            other_user = db.query(User).filter(User.id == other_id).first()
            if other_user:
                dms.append({
                    "id": cid,
                    "name": other_user.full_name or other_user.email,
                    "status": "ENCRYPTED"
                })
        except Exception:
            continue

    return dms


@router.get("/messages")
def get_messages(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
    limit: int = 50,
    channel_id: str = "general"
):
    """
    Fetch and decrypt messages for a channel.
    Extended risk fields included.
    """
    try:
        query = (
            db.query(Message)
            .options(joinedload(Message.reply_to))
            .filter(Message.channel_id == channel_id)
            .filter(
                (Message.expiration == None) |
                (Message.expiration > datetime.utcnow())
            )
        )
        messages = query.order_by(Message.timestamp.asc()).limit(limit).all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    response_messages = []
    for msg in messages:
        sender_type = "me" if msg.sender_id == current_user.id else "them"
        status = "blocked" if msg.is_blocked else "sent"

        # Decrypt content
        plaintext = _decrypt_safe(msg.content_encrypted)

        # Parse stored threat reasons
        try:
            stored_reasons = json.loads(msg.threat_reasons) if msg.threat_reasons else []
        except Exception:
            stored_reasons = []

        risk = {
            "ai_score": msg.ai_score if msg.ai_score is not None else 0.0,
            "opsec_risk": msg.opsec_risk or "SAFE",
            "phishing_risk": msg.phishing_risk or "LOW",
            "explanation": "Analysis complete",
            # Extended
            "severity": msg.severity or "LOW",
            "confidence": int(msg.threat_confidence or 0),
            "model_version": msg.model_version or "heuristic",
            "context_risk": msg.context_risk or "SAFE",
            "reasons": stored_reasons,
            "opsec_score": msg.opsec_score or 0,
            "phishing_confidence": msg.phishing_confidence or 0,
            "ai_method": msg.ai_method or "heuristic",
        }

        reply_to_data = None
        if msg.reply_to:
            reply_sender_type = "me" if msg.reply_to.sender_id == current_user.id else "them"
            reply_to_data = {
                "id": msg.reply_to.id,
                "text": _decrypt_safe(msg.reply_to.content_encrypted),
                "sender": reply_sender_type
            }

        response_messages.append({
            "id": msg.id,
            "text": plaintext,
            "sender": sender_type,
            "timestamp": msg.timestamp,
            "status": status,
            "risk": risk,
            "file_url": msg.file_url,
            "file_type": msg.file_type,
            "file_size": msg.file_size,
            "integrity_hash": msg.integrity_hash,
            "reply_to": reply_to_data,
            "is_deleted": msg.is_deleted,
        })

    return response_messages


class DeleteMessageRequest(BaseModel):
    id: str
    mode: str  # "me" or "everyone"


@router.post("/messages/delete")
def delete_message(
    request: DeleteMessageRequest,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    msg_id = int(request.id)
    msg = db.query(Message).filter(Message.id == msg_id).first()

    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    if request.mode == "everyone":
        msg.is_deleted = True
        db.commit()
    elif request.mode == "me":
        pass  # Frontend-only hide

    return {"success": True}
