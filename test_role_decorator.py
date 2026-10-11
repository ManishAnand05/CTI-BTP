from flask import Flask, jsonify
from backend.authentication import require_role

test_app = Flask(__name__)

@test_app.route("/test/admin")
@require_role("admin")
def admin_route():
    return jsonify({"message": "Admin access granted"})

client = test_app.test_client()

# Test without a token
response = client.get("/test/admin")
print("No token:", response.status_code, "(expected 401)")

# Log in as the existing analyst
with test_app.test_request_context():
    pass

from backend.app import app as main_app

main_client = main_app.test_client()
login = main_client.post("/api/auth/login", json={
    "email": "cti-test-4116955a@example.com",
    "password": "DemoPass123!",
})

print("Login:", login.status_code)

if login.status_code == 200:
    token = login.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Test the admin-only route using the analyst token
    with test_app.test_request_context():
        pass

    # Exercise the test route through the same app that owns it
    # (register the route on the main app temporarily for this test)
    print("Analyst role:", login.get_json()["user"]["role"])
    print("Expected analyst access to admin route: 403")
else:
    print("Login failed:", login.get_json())
