
import os
import re
import sqlite3
from datetime import datetime, timezone

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from backend.database import get_connection


TOKEN_SALT = "cti-auth-token"
TOKEN_MAX_AGE_SECONDS = 3600


def get_token_serializer():
    """Create a signed-token serializer using an environment secret."""
    secret_key = os.environ.get("CTI_SECRET_KEY")

    if not secret_key or len(secret_key) < 32:
        raise RuntimeError(
            "Set CTI_SECRET_KEY to a secret of at least 32 characters."
        )

    return URLSafeTimedSerializer(
        secret_key,
        salt=TOKEN_SALT,
    )


def get_public_user(user):
    """Return safe user details without the password hash."""
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "organization_id": user["organization_id"],
        "role": user["role"],
        "is_active": bool(user["is_active"]),
        "created_at": user["created_at"],
    }


def register_user(name, email, password, organization_id):
    """Register a normal analyst account."""
    name = (name or "").strip()
    email = (email or "").strip().lower()

    if len(name) < 2:
        raise ValueError("Name must contain at least 2 characters.")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")

    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    if not isinstance(organization_id, int) or isinstance(
        organization_id, bool
    ):
        raise ValueError("A valid organization ID is required.")

    connection = get_connection()

    try:
        organization = connection.execute(
            """
            SELECT id, is_active
            FROM organizations
            WHERE id = ?
            """,
            (organization_id,),
        ).fetchone()

        if organization is None:
            raise ValueError("Organization not found.")

        if not organization["is_active"]:
            raise ValueError("Organization is inactive.")

        password_hash = generate_password_hash(password)

        cursor = connection.execute(
            """
            INSERT INTO users (
                name,
                email,
                password_hash,
                organization_id,
                role,
                is_active
            )
            VALUES (?, ?, ?, ?, 'analyst', 1)
            """,
            (name, email, password_hash, organization_id),
        )

        connection.commit()

        user = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

        return get_public_user(user)

    except sqlite3.IntegrityError as error:
        connection.rollback()

        if "users.email" in str(error).lower():
            raise ValueError(
                "An account with this email already exists."
            ) from error

        raise
    finally:
        connection.close()


def authenticate_user(email, password):
    """Verify login credentials for an active user and organization."""
    email = (email or "").strip().lower()

    if not isinstance(password, str) or not password:
        return None

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                users.*,
                organizations.is_active AS organization_is_active
            FROM users
            JOIN organizations
                ON organizations.id = users.organization_id
            WHERE users.email = ?
            """,
            (email,),
        ).fetchone()

        if user is None:
            return None

        if not check_password_hash(user["password_hash"], password):
            return None

        if not user["is_active"] or not user["organization_is_active"]:
            return None

        return get_public_user(user)
    finally:
        connection.close()


def create_access_token(user_id):
    """Create a signed token for an authenticated user."""
    serializer = get_token_serializer()

    return serializer.dumps({
        "user_id": user_id,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    })


def verify_access_token(token):
    """Validate a token and return its current active user."""
    if not token:
        return None

    try:
        data = get_token_serializer().loads(
            token,
            max_age=TOKEN_MAX_AGE_SECONDS,
        )
    except (BadSignature, SignatureExpired, TypeError, ValueError):
        return None

    user_id = data.get("user_id")

    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return None

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                users.*,
                organizations.is_active AS organization_is_active
            FROM users
            JOIN organizations
                ON organizations.id = users.organization_id
            WHERE users.id = ?
            """,
            (user_id,),
        ).fetchone()

        if user is None:
            return None

        if not user["is_active"] or not user["organization_is_active"]:
            return None

        return get_public_user(user)
    finally:
        connection.close()


from functools import wraps
from flask import request, jsonify, g


def require_auth(view_function):
    @wraps(view_function)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            return jsonify({
                "error": "Authentication required"
            }), 401

        token = authorization.split(" ", 1)[1].strip()

        if not token:
            return jsonify({
                "error": "Access token is missing"
            }), 401

        try:
            user = verify_access_token(token)
        except Exception:
            user = None

        if not user:
            return jsonify({
                "error": "Invalid or expired access token"
            }), 401

        g.current_user = user
        return view_function(*args, **kwargs)

    return wrapped


def require_role(*allowed_roles):
    """Allow access only to authenticated users with an allowed role."""
    from functools import wraps
    from flask import request, jsonify, g

    def decorator(view_function):
        @wraps(view_function)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            parts = authorization.split()

            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({
                    "error": "Authentication required"
                }), 401

            try:
                user = verify_access_token(parts[1])
            except Exception:
                user = None

            if not user:
                return jsonify({
                    "error": "Invalid or expired access token"
                }), 401

            if user.get("role") not in allowed_roles:
                return jsonify({
                    "error": "Insufficient permissions"
                }), 403

            g.current_user = user
            return view_function(*args, **kwargs)

        return wrapped

    return decorator
