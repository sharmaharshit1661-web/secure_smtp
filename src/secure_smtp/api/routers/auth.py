"""
Native MongoDB User Authentication Router.

Provides registration, login, session validation, and password hashing
stored directly in MongoDB, with signed JWT access tokens.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from secure_smtp.api.auth import (
    Principal,
    create_access_token,
    hash_password,
    verify_api_key,
    verify_password,
)
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="User full name")
    email: str = Field(..., min_length=4, max_length=120, description="User email address")
    password: str = Field(..., min_length=6, max_length=128, description="User password")
    role: Literal["admin", "member", "analyst"] = Field(
        default="admin", description="Requested role clearance"
    )


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=120, description="User email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class UserResponse(BaseModel):
    user_id: str
    name: str
    email: str
    role: str
    org_id: str


class AuthResponse(BaseModel):
    token: str
    user: UserResponse


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest):
    """Register a new user account with secure password hashing stored in MongoDB."""
    db = get_database()
    email_clean = body.email.strip().lower()

    if not ("@" in email_clean and "." in email_clean):
        raise HTTPException(status_code=400, detail="Invalid email format")

    existing = db.users.find_one({"email": email_clean})
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    settings = get_settings()
    user_id = f"usr_{uuid.uuid4().hex[:12]}"
    org_id = settings.pilot_org_id or f"org_{user_id}"

    # First user or admin role gets admin privileges
    role = body.role if body.role in ("admin", "member", "analyst") else "admin"

    user_doc = {
        "user_id": user_id,
        "name": body.name.strip(),
        "email": email_clean,
        "password_hash": hash_password(body.password),
        "role": role,
        "org_id": org_id,
        "created_at": datetime.now(UTC),
    }

    try:
        db.users.insert_one(user_doc)
    except Exception as exc:
        logger.error("Failed to insert user into MongoDB: %s", exc)
        raise HTTPException(status_code=500, detail="Database registration failed") from exc

    token = create_access_token(
        user_id=user_id,
        email=email_clean,
        role=role,
        org_id=org_id,
    )

    return AuthResponse(
        token=token,
        user=UserResponse(
            user_id=user_id,
            name=user_doc["name"],
            email=email_clean,
            role=role,
            org_id=org_id,
        ),
    )


@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest):
    """Sign in using MongoDB credentials and receive a signed JWT access token."""
    db = get_database()
    email_clean = body.email.strip().lower()

    user = db.users.find_one({"email": email_clean})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    settings = get_settings()
    user_id = user["user_id"]
    org_id = user.get("org_id") or settings.pilot_org_id or f"org_{user_id}"
    role = user.get("role", "admin")

    token = create_access_token(
        user_id=user_id,
        email=email_clean,
        role=role,
        org_id=org_id,
    )

    return AuthResponse(
        token=token,
        user=UserResponse(
            user_id=user_id,
            name=user.get("name", "Operator"),
            email=email_clean,
            role=role,
            org_id=org_id,
        ),
    )


@router.post("/demo", response_model=AuthResponse)
def demo_login():
    """Instant 1-click access for evaluation and demonstration."""
    db = get_database()
    settings = get_settings()

    demo_email = "analyst@corp.io"
    user = db.users.find_one({"email": demo_email})
    if not user:
        user_id = "usr_demo_analyst"
        org_id = settings.pilot_org_id or "pilot"
        user = {
            "user_id": user_id,
            "name": "SOC Lead Administrator",
            "email": demo_email,
            "password_hash": hash_password("SecureCipher2026!"),
            "role": "admin",
            "org_id": org_id,
            "created_at": datetime.now(UTC),
        }
        try:
            db.users.update_one({"email": demo_email}, {"$setOnInsert": user}, upsert=True)
        except Exception:
            pass
    else:
        user_id = user["user_id"]
        org_id = user.get("org_id") or settings.pilot_org_id or "pilot"

    token = create_access_token(
        user_id=user_id,
        email=demo_email,
        role=user.get("role", "admin"),
        org_id=org_id,
    )

    return AuthResponse(
        token=token,
        user=UserResponse(
            user_id=user_id,
            name=user.get("name", "SOC Lead Administrator"),
            email=demo_email,
            role=user.get("role", "admin"),
            org_id=org_id,
        ),
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(principal: Principal = Depends(verify_api_key)):
    """Retrieve the currently authenticated user profile."""
    db = get_database()
    user = db.users.find_one({"user_id": principal.user_id}) or db.users.find_one(
        {"email": principal.user_id}
    )

    name = user.get("name") if user else "Security Analyst"
    email = user.get("email") if user else principal.user_id

    return UserResponse(
        user_id=principal.user_id,
        name=name,
        email=email,
        role=principal.role,
        org_id=principal.org_id,
    )
