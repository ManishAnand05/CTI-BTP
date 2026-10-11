from backend.app import app

client = app.test_client()

routes = [
    "/api/cti",
    "/api/correlations",
    "/api/risk",
]

print("Testing protected GET endpoints:")
for route in routes:
    response = client.get(route)
    print(f"{route}: HTTP {response.status_code}")
