
import uuid

from backend.app import app

client = app.test_client()

email = f"cti-test-{uuid.uuid4().hex[:8]}@example.com"
password = "DemoPass123!"

# 1. Test registration
response = client.post(
    "/api/auth/register",
    json={
        "name": "CTI Test User",
        "email": email,
        "password": password,
        "organization_id": 1,
    },
)

print("Registration status:", response.status_code)
print("Registration response:", response.get_json())

# 2. Test login
response = client.post(
    "/api/auth/login",
    json={
        "email": email,
        "password": password,
    },
)

print("Login status:", response.status_code)

token = None

if response.status_code == 200:
    token = response.get_json().get("access_token")

print("Token returned:", bool(token))

# 3. Test token verification
if token:
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    print("Token verification status:", response.status_code)
else:
    print("Token verification skipped because login failed.")

# 4. Test incorrect password
response = client.post(
    "/api/auth/login",
    json={
        "email": email,
        "password": "WrongPass123!",
    },
)

print("Wrong password status:", response.status_code)
print("Wrong password rejected:", response.status_code == 401)
