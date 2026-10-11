from backend.database import (
    get_connection,
    get_organization_by_id as db_get_organization_by_id,
    register_organization as db_register_organization,
    update_organization as db_update_organization,
    update_organization_trust_score as db_update_trust_score,
    update_policy_violations as db_update_policy_violations,
    set_organization_status as db_set_organization_status,
)


def get_trust_level(score):
    """Convert a numeric trust score into a readable level."""
    if score >= 80:
        return "high"
    elif score >= 50:
        return "medium"
    return "low"


def _format_organization(organization):
    """Add derived fields to an organization dictionary."""
    if organization is None:
        return None

    organization["trust_level"] = get_trust_level(
        organization["trust_score"]
    )
    organization["is_active"] = bool(organization["is_active"])

    return organization


def register_organization(name, sector, trust_score=50):
    """Register a new organization."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Organization name is required")

    if not isinstance(sector, str) or not sector.strip():
        raise ValueError("Organization sector is required")

    if type(trust_score) is not int or not 0 <= trust_score <= 100:
        raise ValueError("Trust score must be an integer from 0 to 100")

    organization_id = db_register_organization(
        name.strip(),
        sector.strip(),
        trust_score,
    )

    return organization_id


def get_all_organizations():
    """Return all organizations with derived trust levels."""
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                name,
                sector,
                trust_score,
                policy_violations,
                is_active,
                created_at
            FROM organizations
            ORDER BY id
        """).fetchall()

    return [
        _format_organization(dict(row))
        for row in rows
    ]


def get_organization(organization_id):
    """Retrieve one organization by ID."""
    return _format_organization(
        db_get_organization_by_id(organization_id)
    )


def update_organization(organization_id, name=None, sector=None):
    """Update an organization's name and/or sector."""
    return db_update_organization(
        organization_id,
        name=name,
        sector=sector,
    )


def update_trust_score(organization_id, trust_score):
    """Update an organization's trust score."""
    return db_update_trust_score(
        organization_id,
        trust_score,
    )


def update_policy_violations(organization_id, policy_violations):
    """Set the current policy-violation count."""
    return db_update_policy_violations(
        organization_id,
        policy_violations,
    )


def set_organization_status(organization_id, is_active):
    """Activate or deactivate an organization."""
    return db_set_organization_status(
        organization_id,
        is_active,
    )
