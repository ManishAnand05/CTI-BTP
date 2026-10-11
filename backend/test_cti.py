
from backend.cti_processor import process_cti

result = process_cti(
    ip_address="198.51.100.25",
    description="Example suspicious IP for testing",
    severity="high"
)

print(result)
