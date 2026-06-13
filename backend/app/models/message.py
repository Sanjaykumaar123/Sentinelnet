from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.base import Base

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    
    # ── Encryption ─────────────────────────────────────────────────────────
    # Stores base64(iv + tag + ciphertext) — plaintext NEVER persisted
    content_encrypted = Column(Text)
    encryption_version = Column(String, default="AES-256-GCM-v1", nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # ── Threat Analysis (legacy + extended) ────────────────────────────────
    ai_score = Column(Float)                       # 0–100 AI-generation probability
    opsec_risk = Column(String)                    # "SAFE" | "SENSITIVE" | "HIGH"
    phishing_risk = Column(String)                 # "LOW" | "MODERATE" | "HIGH"
    is_blocked = Column(Boolean, default=False)

    # Extended threat fields (new)
    severity = Column(String, nullable=True)       # "LOW" | "MEDIUM" | "HIGH"
    threat_confidence = Column(Float, nullable=True)  # 0–100 overall confidence
    model_version = Column(String, nullable=True)  # which model was used
    context_risk = Column(String, nullable=True)   # cross-message context risk
    threat_reasons = Column(Text, nullable=True)   # JSON array of reason strings
    opsec_score = Column(Float, nullable=True)
    phishing_confidence = Column(Float, nullable=True)
    ai_method = Column(String, nullable=True)      # "transformer" | "heuristic"

    # ── Security ───────────────────────────────────────────────────────────
    integrity_hash = Column(String, nullable=True) # HMAC-SHA256 of plaintext
    nonce = Column(String, nullable=True)          # anti-replay nonce (UUID)
    audit_log = Column(Text, nullable=True)        # JSON audit events

    # ── File Sharing ───────────────────────────────────────────────────────
    file_url = Column(String, nullable=True)
    file_type = Column(String, nullable=True)
    file_size = Column(String, nullable=True)

    # ── Channels / DM ──────────────────────────────────────────────────────
    channel_id = Column(String, index=True, default="general")
    receiver_id = Column(Integer, nullable=True)
    reply_to_id = Column(Integer, ForeignKey("messages.id"), nullable=True)

    # ── Lifecycle ──────────────────────────────────────────────────────────
    expiration = Column(DateTime, nullable=True)   # Self-destruct time
    is_deleted = Column(Boolean, default=False)

    sender = relationship("User")
    reply_to = relationship("Message", remote_side=[id])
