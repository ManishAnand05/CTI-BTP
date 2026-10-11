import uuid
from backend.app import app

client = app.test_client()
email = f"cti-test-{uuid.uuid4().hex[:8]}@example.com"
password = "DemoPass123!"

# Registration
r = client.post("/api/auth/register", json={
    "name": "CTI Test User",
    "email": email,
    "password": password,
    "organization_id": 1,
})
print("Registration:", r.status_code, r.get_json())

# Login
r = client.post("/api/auth/login", json={
    "email": email,
    "password": password,
})
print("Login:", r.status_code)

token = r.get_json().get("access_token") if r.status_code == 200 else None
print("Token returned:", bool(token))

# Verify token
if token:
    r = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    print("Token verification:", r.status_code)
else:
    print("Token verification: skipped")

# Reject incorrect password
r = client.post("/api/auth/login", json={
    "email": email,
    "password": "WrongPass123!",
})
print("Wrong password rejected:", r.status_code == 401)
