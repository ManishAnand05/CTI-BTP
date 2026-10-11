from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import ipaddress
import sqlite3
from backend.authentication import (
    register_user,
    authenticate_user,
    create_access_token,
    verify_access_token,
    require_auth,
)
from backend.cti_processor import process_cti
from backend.database import (
    initialize_database,
    save_indicator,
    get_all_indicators,
)
from backend.correlation import correlate_indicators
from backend.risk_analysis import calculate_risk
from backend.organizations import (
    register_organization,
    get_all_organizations,
    get_organization,
    update_organization,
    update_trust_score,
    update_policy_violations,
    set_organization_status,
    get_trust_level,
)
from backend.policy_engine import (
    generate_access_policy,
    generate_advanced_access_policy,
)
from backend.advanced_cti import advanced_cti_bp
app = Flask(__name__)
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
        }
    },
)

# Register advanced CTI endpoints.
app.register_blueprint(advanced_cti_bp)

# Initialize database without deleting existing data.
initialize_database()

# --------------------------------------------------

# Helper functions

# --------------------------------------------------
def valid_positive_id(value):
    return type(value) is int and value > 0
def organization_not_found_response(organization_id):
    return jsonify({
        "error": "Organization not found",
        "organization_id": organization_id,
    }), 404

# --------------------------------------------------

# 1. Home API

# --------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "CTI-BTP",
        "status": "Backend running",
        "message": "Cyber Threat Intelligence API is ready",
    }), 200

# --------------------------------------------------

# 2. Submit and process legacy CTI

# --------------------------------------------------
@app.route("/api/cti", methods=["POST"])
def receive_cti():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    ip_address = data.get("ip_address")
    description = data.get("description")
    severity = data.get("severity")
    sharing_sector = data.get("sharing_sector", "All")
    if not all([ip_address, description, severity]):
        return jsonify({
            "error": (
                "ip_address, description, and severity are required"
            )
        }), 400
    if not isinstance(ip_address, str):
        return jsonify({"error": "IP address must be text"}), 400
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.version != 4:
            return jsonify({
                "error": "Only IPv4 addresses are supported"
            }), 400
    except ValueError:
        return jsonify({"error": "Invalid IPv4 address"}), 400
    if not isinstance(description, str) or not description.strip():
        return jsonify({
            "error": "Description must be a non-empty string"
        }), 400
    if not isinstance(severity, str):
        return jsonify({"error": "Severity must be text"}), 400
    severity = severity.strip().lower()
    if severity not in ["low", "medium", "high", "critical"]:
        return jsonify({
            "error": "Severity must be low, medium, high, or critical"
        }), 400
    if not isinstance(sharing_sector, str) or not sharing_sector.strip():
        return jsonify({
            "error": "sharing_sector must be a non-empty string"
        }), 400
    supported_sectors = [
        "Finance",
        "Healthcare",
        "Education",
        "Technology",
        "Government",
        "Energy",
    ]
    sharing_sector = sharing_sector.strip()
    if sharing_sector.lower() == "all":
        sharing_sector = "All"
    else:
        matched_sector = next(
            (
                sector
                for sector in supported_sectors
                if sector.lower() == sharing_sector.lower()
            ),
            None,
        )
        if matched_sector is None:
            return jsonify({
                "error": "Unsupported sharing sector",
                "supported_sectors": supported_sectors + ["All"],
            }), 400
        sharing_sector = matched_sector
    try:
        result = process_cti(
            ip_address=str(ip_obj),
            description=description.strip(),
            severity=severity,
        )
        stix_json = result["stix_data"]
        record_id = save_indicator(
            ip_address=str(ip_obj),
            description=description.strip(),
            severity=severity,
            stix_data=stix_json,
            sharing_sector=sharing_sector,
        )
        return jsonify({
            "message": "CTI processed and saved successfully",
            "record_id": record_id,
            "ip_address": str(ip_obj),
            "severity": severity,
            "sharing_sector": sharing_sector,
            "stix_data": json.loads(stix_json),
        }), 201
    except Exception:
        app.logger.exception("CTI processing or storage failed")
        return jsonify({
            "error": "CTI processing or storage failed"
        }), 500

# --------------------------------------------------

# 3. Retrieve legacy CTI indicators

# --------------------------------------------------
@app.route("/api/cti", methods=["GET"])
@require_auth
def list_cti():
    try:
        records = get_all_indicators()
        for record in records:
            record["stix_data"] = json.loads(record["stix_data"])
        return jsonify({
            "count": len(records),
            "indicators": records,
        }), 200
    except Exception:
        app.logger.exception("Failed to retrieve CTI")
        return jsonify({
            "error": "Failed to retrieve CTI records"
        }), 500

# --------------------------------------------------

# 4. Correlate CTI indicators

# --------------------------------------------------
@app.route("/api/correlations", methods=["GET"])
@require_auth
def list_correlations():
    try:
        results = correlate_indicators()
        return jsonify({
            "count": len(results),
            "correlations": results,
        }), 200
    except Exception:
        app.logger.exception("CTI correlation failed")
        return jsonify({
            "error": "CTI correlation failed"
        }), 500

# --------------------------------------------------

# 5. Calculate legacy CTI risk scores

# --------------------------------------------------
@app.route("/api/risk", methods=["GET"])
@require_auth
def get_risk_analysis():
    try:
        results = calculate_risk()
        return jsonify({
            "scoring_model": "CTI-BTP prototype scoring v1",
            "count": len(results),
            "results": results,
        }), 200
    except Exception:
        app.logger.exception("Risk analysis failed")
        return jsonify({
            "error": "Risk analysis failed"
        }), 500

# --------------------------------------------------

# 6. Register an organization

# --------------------------------------------------
@app.route("/api/organizations", methods=["POST"])
def create_organization():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    name = data.get("name")
    sector = data.get("sector")
    trust_score = data.get("trust_score", 50)
    if not isinstance(name, str) or not name.strip():
        return jsonify({
            "error": "Organization name is required"
        }), 400
    if not isinstance(sector, str) or not sector.strip():
        return jsonify({
            "error": "Organization sector is required"
        }), 400
    if type(trust_score) is not int or not 0 <= trust_score <= 100:
        return jsonify({
            "error": "trust_score must be an integer from 0 to 100"
        }), 400
    try:
        organization_id = register_organization(
            name.strip(),
            sector.strip(),
            trust_score,
        )
        organization = get_organization(organization_id)
        return jsonify({
            "message": "Organization registered successfully",
            "organization": organization,
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Organization name already exists"
        }), 409
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Organization registration failed")
        return jsonify({
            "error": "Organization registration failed"
        }), 500

# --------------------------------------------------

# 7. List all organizations

# --------------------------------------------------
@app.route("/api/organizations", methods=["GET"])
def list_organizations():
    try:
        organizations = get_all_organizations()
        return jsonify({
            "count": len(organizations),
            "organizations": organizations,
        }), 200
    except Exception:
        app.logger.exception("Organization retrieval failed")
        return jsonify({
            "error": "Organization retrieval failed"
        }), 500

# --------------------------------------------------

# 8. Retrieve one organization

# --------------------------------------------------
@app.route("/api/organizations/<int:organization_id>", methods=["GET"])
def retrieve_organization(organization_id):
    organization = get_organization(organization_id)
    if organization is None:
        return organization_not_found_response(organization_id)
    return jsonify({"organization": organization}), 200

# --------------------------------------------------

# 9. Update organization name and/or sector

# --------------------------------------------------
@app.route("/api/organizations/<int:organization_id>", methods=["PUT"])
def edit_organization(organization_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    allowed_fields = {"name", "sector"}
    if not data or not set(data).issubset(allowed_fields):
        return jsonify({
            "error": "Provide name and/or sector only"
        }), 400
    try:
        updated = update_organization(
            organization_id,
            name=data.get("name"),
            sector=data.get("sector"),
        )
        if not updated:
            return organization_not_found_response(organization_id)
        return jsonify({
            "message": "Organization updated successfully",
            "organization": get_organization(organization_id),
        }), 200
    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Organization name already exists"
        }), 409
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Organization update failed")
        return jsonify({
            "error": "Organization update failed"
        }), 500

# --------------------------------------------------

# 10. Update organization trust score

# --------------------------------------------------
@app.route(
    "/api/organizations/<int:organization_id>/trust",
    methods=["PATCH"],
)
def edit_organization_trust(organization_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    trust_score = data.get("trust_score")
    if type(trust_score) is not int or not 0 <= trust_score <= 100:
        return jsonify({
            "error": "trust_score must be an integer from 0 to 100"
        }), 400
    try:
        updated = update_trust_score(organization_id, trust_score)
        if not updated:
            return organization_not_found_response(organization_id)
        return jsonify({
            "message": "Trust score updated successfully",
            "organization": get_organization(organization_id),
        }), 200
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Trust score update failed")
        return jsonify({
            "error": "Trust score update failed"
        }), 500

# --------------------------------------------------

# 11. Update policy violation count

# --------------------------------------------------
@app.route(
    "/api/organizations/<int:organization_id>/violations",
    methods=["PATCH"],
)
def edit_organization_violations(organization_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    policy_violations = data.get("policy_violations")
    if (
        type(policy_violations) is not int
        or policy_violations < 0
    ):
        return jsonify({
            "error": "policy_violations must be a non-negative integer"
        }), 400
    try:
        updated = update_policy_violations(
            organization_id,
            policy_violations,
        )
        if not updated:
            return organization_not_found_response(organization_id)
        return jsonify({
            "message": "Policy violations updated successfully",
            "organization": get_organization(organization_id),
        }), 200
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Policy violation update failed")
        return jsonify({
            "error": "Policy violation update failed"
        }), 500

# --------------------------------------------------

# 12. Activate or deactivate an organization

# --------------------------------------------------
@app.route(
    "/api/organizations/<int:organization_id>/status",
    methods=["PATCH"],
)
def edit_organization_status(organization_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    is_active = data.get("is_active")
    if type(is_active) is not bool:
        return jsonify({
            "error": "is_active must be true or false"
        }), 400
    try:
        updated = set_organization_status(
            organization_id,
            is_active,
        )
        if not updated:
            return organization_not_found_response(organization_id)
        return jsonify({
            "message": "Organization status updated successfully",
            "organization": get_organization(organization_id),
        }), 200
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Organization status update failed")
        return jsonify({
            "error": "Organization status update failed"
        }), 500

# --------------------------------------------------

# 13. Evaluate access to a legacy CTI indicator

# --------------------------------------------------
@app.route("/api/policies", methods=["POST"])
def evaluate_policy():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    organization_id = data.get("organization_id")
    indicator_id = data.get("indicator_id")
    if not valid_positive_id(organization_id):
        return jsonify({
            "error": "organization_id must be a positive integer"
        }), 400
    if not valid_positive_id(indicator_id):
        return jsonify({
            "error": "indicator_id must be a positive integer"
        }), 400
    try:
        result = generate_access_policy(
            organization_id,
            indicator_id,
        )
        if result.get("reason") in [
            "Organization not found",
            "CTI indicator not found",
            "Risk assessment not available",
        ]:
            return jsonify(result), 404
        return jsonify(result), 200
    except Exception:
        app.logger.exception("Access policy evaluation failed")
        return jsonify({
            "error": "Access policy evaluation failed"
        }), 500

# --------------------------------------------------

# 14. Evaluate access to an advanced CTI record

# --------------------------------------------------
@app.route("/api/advanced-policies", methods=["POST"])
def advanced_access_policy():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    organization_id = data.get("organization_id")
    record_id = data.get("record_id")
    if not valid_positive_id(organization_id):
        return jsonify({
            "error": "organization_id must be a positive integer"
        }), 400
    if not valid_positive_id(record_id):
        return jsonify({
            "error": "record_id must be a positive integer"
        }), 400
    try:
        result = generate_advanced_access_policy(
            organization_id,
            record_id,
        )
        if result.get("reason") in [
            "Organization not found",
            "Advanced CTI record not found",
        ]:
            return jsonify(result), 404
        return jsonify(result), 200
    except Exception:
        app.logger.exception(
            "Advanced CTI access policy evaluation failed"
        )
        return jsonify({
            "error": "Advanced CTI access policy evaluation failed"
        }), 500

# --------------------------------------------------

# 15. Authentication APIs

# --------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    try:
        user = register_user(
            name=data.get("name"),
            email=data.get("email"),
            password=data.get("password"),
            organization_id=data.get("organization_id"),
        )
        return jsonify({
            "message": "Registration successful",
            "user": user,
        }), 201
    except ValueError as error:
        message = str(error)
        if "already exists" in message.lower():
            return jsonify({"error": message}), 409
        return jsonify({"error": message}), 400
    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Email or organization constraint failed"
        }), 409
    except Exception:
        app.logger.exception("User registration failed")
        return jsonify({"error": "Registration failed"}), 500
@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object"}), 400
    email = data.get("email")
    password = data.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({
            "error": "Email and password are required"
        }), 400
    try:
        user = authenticate_user(email, password)
        if user is None:
            return jsonify({
                "error": "Invalid credentials or inactive account"
            }), 401
        token = create_access_token(user["id"])
        return jsonify({
            "message": "Login successful",
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "user": user,
        }), 200
    except Exception:
        app.logger.exception("Login failed")
        return jsonify({"error": "Login failed"}), 500
@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({
            "error": "Provide a Bearer access token"
        }), 401
    try:
        user = verify_access_token(parts[1])
        if user is None:
            return jsonify({
                "error": "Invalid, expired, or inactive token"
            }), 401
        return jsonify({"user": user}), 200
    except Exception:
        app.logger.exception("Token verification failed")
        return jsonify({
            "error": "Token verification failed"
        }), 500

# --------------------------------------------------

# Advanced CTI routes

# Registered through advanced_cti_bp.

#

# POST /api/cti/submit

# GET  /api/cti/advanced

# GET  /api/cti/advanced/<record_id>/submissions

# --------------------------------------------------

# --------------------------------------------------

# Start Flask

# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
