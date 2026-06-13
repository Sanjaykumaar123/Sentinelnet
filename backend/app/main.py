import sys
import os

# Fix Vercel Import Path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import traceback

from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as api_router
from app.db.session import SessionLocal, engine, DB_CONNECTION_ERROR
from app.db.base import Base
from app.models.user import User
from app.models.message import Message
from app.core import security
from sqlalchemy import text

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ────────────────────────────────────────────────────────────
    try:
        print(f"DATABASE CONNECTING TO: {str(engine.url)[:20]}...")

        try:
            Base.metadata.create_all(bind=engine)

            # Auto-migrate existing DBs with new columns
            new_columns = [
                ("file_url", "VARCHAR"),
                ("file_type", "VARCHAR"),
                ("file_size", "VARCHAR"),
                ("integrity_hash", "VARCHAR"),
                ("channel_id", "VARCHAR"),
                ("expiration", "TIMESTAMP"),
                ("receiver_id", "INTEGER"),
                ("reply_to_id", "INTEGER"),
                ("is_deleted", "BOOLEAN DEFAULT FALSE"),
                ("ai_score", "FLOAT"),
                ("opsec_risk", "VARCHAR"),
                ("phishing_risk", "VARCHAR"),
                ("is_blocked", "BOOLEAN DEFAULT FALSE"),
                # New: extended threat + encryption columns
                ("encryption_version", "VARCHAR"),
                ("severity", "VARCHAR"),
                ("threat_confidence", "FLOAT"),
                ("model_version", "VARCHAR"),
                ("context_risk", "VARCHAR"),
                ("threat_reasons", "TEXT"),
                ("opsec_score", "FLOAT"),
                ("phishing_confidence", "FLOAT"),
                ("ai_method", "VARCHAR"),
                ("nonce", "VARCHAR"),
                ("audit_log", "TEXT"),
            ]
            with engine.connect() as conn:
                for col_name, col_type in new_columns:
                    try:
                        conn.execute(
                            text(f"ALTER TABLE messages ADD COLUMN IF NOT EXISTS {col_name} {col_type}")
                        )
                    except Exception:
                        pass
                conn.commit()

            # Create default admin user
            db = SessionLocal()
            try:
                if not db.query(User).filter(User.email == "admin@sentinel.net").first():
                    user = User(
                        email="admin@sentinel.net",
                        hashed_password=security.get_password_hash("admin"),
                        full_name="Commander Shepard",
                        role="admin",
                        is_active=True
                    )
                    db.add(user)
                    db.commit()
            except Exception as e:
                print(f"Error creating default user: {e}")
            finally:
                db.close()

        except Exception as db_exc:
            print(f"CRITICAL DATABASE ERROR: {db_exc}")

        # ── Initialize AI Threat Engine (non-blocking, background thread) ──
        try:
            from app.services.threat_intel import initialize_threat_engine
            import asyncio
            asyncio.ensure_future(initialize_threat_engine())
            print("[OK] Threat engine initialization started in background")
        except Exception as te:
            print(f"Threat engine startup soft-fail: {te}")

    except Exception as e:
        print(f"Startup Error: {e}")

    yield
    # Shutdown


app = FastAPI(
    title="SentinelNet API",
    version="2.0.0",
    description="AI-Powered Secure Communication Platform",
    lifespan=lifespan
)


@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Server Error: {str(exc)} Trace: {traceback.format_exc()}"},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/")
def read_root():
    from app.services.threat_intel import get_model_status
    return {
        "message": "SentinelNet Secure Gateway Active — AI-Powered v2.0",
        "env": "production",
        "tables": list(Base.metadata.tables.keys()),
        "db_url_masked": str(engine.url)[:15] + "...",
        "threat_engine": get_model_status(),
    }


@app.get("/api/health")
def health_check():
    from app.services.threat_intel import get_model_status
    db = SessionLocal()
    user_count = 0
    first_user = "None"
    try:
        user_count = db.query(User).count()
        u = db.query(User).first()
        if u:
            first_user = u.email
    except Exception as e:
        first_user = f"Error: {e}"
    finally:
        db.close()

    return {
        "status": "operational",
        "env_vercel": os.getenv("VERCEL"),
        "db_type": str(engine.url),
        "user_count": user_count,
        "first_user_email": first_user,
        "tables": list(Base.metadata.tables.keys()),
        "db_url_masked": str(engine.url)[:15] + "...",
        "db_connection_error": str(DB_CONNECTION_ERROR) if DB_CONNECTION_ERROR else None,
        "threat_engine": get_model_status(),
    }


@app.get("/api/debug/users")
def debug_users():
    """List all users (debug only)."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return [
            {
                "id": u.id,
                "email": u.email,
                "created_at": "Unknown",
                "role": u.role,
                "is_active": u.is_active,
            }
            for u in users
        ]
    except Exception as e:
        return {"error": str(e)}
    finally:
        db.close()
