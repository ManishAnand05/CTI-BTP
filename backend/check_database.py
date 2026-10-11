
from backend.database import get_connection

connection = get_connection()

print("Tables:")
tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
).fetchall()

for table in tables:
    print("-", table["name"])

organizations = connection.execute(
    "SELECT COUNT(*) FROM organizations"
).fetchone()[0]

indicators = connection.execute(
    "SELECT COUNT(*) FROM indicators"
).fetchone()[0]

print("\nExisting organizations:", organizations)
print("Existing indicators:", indicators)

connection.close()
