from backend.app import app

client = app.test_client()

# Log in with the test account created earlier
login_response = client.post("/api/auth/login", json={
    "email": "cti-test-4116955a@example.com",
    "password": "DemoPass123!",
})

print("Login status:", login_response.status_code)

if login_response.status_code != 200:
    print("Login failed:", login_response.get_json())
    raise SystemExit(1)

token = login_response.get_json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

routes = [
    "/api/cti",
    "/api/correlations",
    "/api/risk",
]

print("\nTesting protected endpoints with a valid token:")
for route in routes:
    response = client.get(route, headers=headers)
    print(f"{route}: HTTP {response.status_code}")
