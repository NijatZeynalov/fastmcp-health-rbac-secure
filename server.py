from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict, cast

import jwt
from dotenv import load_dotenv
from fastmcp import Context, FastMCP
from fastmcp.exceptions import McpError, NotFoundError
from jwt import ExpiredSignatureError, InvalidTokenError

load_dotenv()

LOGGER = logging.getLogger("patient_rbac_mcp")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

APP_DIR = Path(__file__).resolve().parent
DEFAULT_DB_URL = "sqlite:///app.db"


class VitalUpdate(TypedDict, total=False):
    blood_pressure: str
    heart_rate: int
    respiratory_rate: int
    temperature: float
    notes: str


PermissionToolMapping: dict[str, list[str]] = {
    "Doctor": ["ViewPatientHistory", "UpdateDiagnosis", "OrderLabTest"],
    "Nurse": ["ViewPatientHistory", "UpdateVitals", "RecordNurseNotes"],
    "LabTechnician": ["ViewLabOrders", "EnterLabResults"],
    "AdminStaff": ["ScheduleAppointment", "BillingInfoView"],
}

TOOL_TO_ROLES: dict[str, set[str]] = {}
for role, tools in PermissionToolMapping.items():
    for tool in tools:
        TOOL_TO_ROLES.setdefault(tool, set()).add(role)

WRITE_TOOLS = {
    "UpdateDiagnosis",
    "OrderLabTest",
    "UpdateVitals",
    "RecordNurseNotes",
    "EnterLabResults",
    "ScheduleAppointment",
}

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET missing. Please define it inside your .env file.")

JWT_ALGORITHM = "HS256"


def _resolve_db_path(db_url: str | None) -> Path:
    raw = (db_url or DEFAULT_DB_URL).strip()
    prefix = "sqlite:///"
    if raw.startswith(prefix):
        raw = raw[len(prefix) :]
    path = Path(raw)
    if not path.is_absolute():
        path = (APP_DIR / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


DB_PATH = _resolve_db_path(os.getenv("DB_URL"))


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _hash_password(raw_password: str) -> str:
    return hashlib.sha256(raw_password.encode("utf-8")).hexdigest()

# use only once
def init_db() -> None:
    statements = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            mrn TEXT UNIQUE NOT NULL,
            date_of_birth TEXT,
            diagnosis TEXT,
            primary_physician TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS vitals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            recorded_at TEXT NOT NULL,
            blood_pressure TEXT,
            heart_rate INTEGER,
            temperature REAL,
            respiratory_rate INTEGER,
            notes TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS lab_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            test_name TEXT NOT NULL,
            status TEXT NOT NULL,
            ordered_by TEXT,
            ordered_at TEXT NOT NULL,
            result TEXT,
            result_entered_by TEXT,
            fulfilled_at TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS billing (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            insurance_provider TEXT,
            policy_number TEXT,
            outstanding_balance REAL,
            last_payment_date TEXT,
            notes TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            appointment_date TEXT NOT NULL,
            provider TEXT NOT NULL,
            reason TEXT,
            status TEXT,
            scheduled_by TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS nurse_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            recorded_by TEXT,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_email TEXT,
            actor_role TEXT,
            tool_name TEXT NOT NULL,
            target_id TEXT,
            payload TEXT,
            created_at TEXT NOT NULL
        )
        """,
    ]

    with get_connection() as conn:
        for statement in statements:
            conn.execute(statement)
        conn.commit()


def seed_data() -> None:
    with get_connection() as conn:
        existing = conn.execute("SELECT COUNT(1) FROM patients").fetchone()[0]
        if existing:
            return

        LOGGER.info("Seeding initial SQLite data at %s", DB_PATH)
        staff = [
            ("Dr. Jamil Mammadov", "Doctor", "dr.jamil@hospital.test", _hash_password("docpass")),
            ("Nurse Leyla Aliyeva", "Nurse", "nurse.leyla@hospital.test", _hash_password("nursepass")),
            ("Lab Tech Arif", "LabTechnician", "lab.arif@hospital.test", _hash_password("labpass")),
            ("Admin Samir", "AdminStaff", "admin.samir@hospital.test", _hash_password("adminpass")),
        ]
        conn.executemany(
            """
            INSERT INTO users (name, role, email, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            staff,
        )

        patients = [
            ("Patient A", "A1001", "1986-04-12", "Hypertension", "Dr. Jamil Mammadov"),
            ("Patient B", "B2002", "1992-09-30", "Type 2 Diabetes", "Dr. Jamil Mammadov"),
            ("Patient C", "C3003", "1978-01-25", "Hyperlipidemia", "Dr. Jamil Mammadov"),
        ]
        conn.executemany(
            """
            INSERT INTO patients (full_name, mrn, date_of_birth, diagnosis, primary_physician)
            VALUES (?, ?, ?, ?, ?)
            """,
            patients,
        )

        now = datetime.utcnow()

        vitals = [
            (1, (now - timedelta(days=2)).isoformat(), "118/76", 72, 36.8, 16, "Stable"),
            (1, (now - timedelta(days=1)).isoformat(), "122/80", 75, 36.9, 17, "Slight headache"),
            (2, (now - timedelta(days=1)).isoformat(), "130/85", 80, 37.0, 18, "Complained of fatigue"),
            (3, now.isoformat(), "116/74", 70, 36.7, 16, "Baseline"),
        ]
        conn.executemany(
            """
            INSERT INTO vitals (
                patient_id, recorded_at, blood_pressure, heart_rate,
                temperature, respiratory_rate, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            vitals,
        )

        lab_orders = [
            (1, "Complete Blood Count", "completed", "dr.jamil@hospital.test", (now - timedelta(days=3)).isoformat(), "Normal limits", "lab.arif@hospital.test", (now - timedelta(days=2)).isoformat()),
            (2, "HbA1c", "ordered", "dr.jamil@hospital.test", (now - timedelta(days=1)).isoformat(), None, None, None),
            (3, "Lipid Panel", "completed", "dr.jamil@hospital.test", (now - timedelta(days=7)).isoformat(), "LDL elevated", "lab.arif@hospital.test", (now - timedelta(days=6)).isoformat()),
        ]
        conn.executemany(
            """
            INSERT INTO lab_orders (
                patient_id, test_name, status, ordered_by, ordered_at,
                result, result_entered_by, fulfilled_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            lab_orders,
        )

        billing_rows = [
            (1, "AzInsurance", "AZ-33221", 125.50, (now - timedelta(days=10)).date().isoformat(), "Co-pay pending"),
            (2, "CarePlus", "CP-99881", 0.0, (now - timedelta(days=35)).date().isoformat(), "Settled"),
            (3, "GlobalHealth", "GH-55119", 890.75, None, "Awaiting insurance response"),
        ]
        conn.executemany(
            """
            INSERT INTO billing (
                patient_id, insurance_provider, policy_number,
                outstanding_balance, last_payment_date, notes
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            billing_rows,
        )

        appointments = [
            (1, (now + timedelta(days=3)).isoformat(), "Dr. Jamil Mammadov", "Follow-up", "scheduled", "admin.samir@hospital.test"),
            (2, (now + timedelta(days=7)).isoformat(), "Nutrition Team", "Diet review", "scheduled", "admin.samir@hospital.test"),
            (3, (now + timedelta(days=1)).isoformat(), "Dr. Jamil Mammadov", "Medication review", "scheduled", "admin.samir@hospital.test"),
        ]
        conn.executemany(
            """
            INSERT INTO appointments (
                patient_id, appointment_date, provider, reason, status, scheduled_by
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            appointments,
        )

        nurse_notes = [
            (1, "Patient responded well to medication adjustment.", "nurse.leyla@hospital.test", (now - timedelta(hours=20)).isoformat()),
            (2, "Educated patient on insulin administration.", "nurse.leyla@hospital.test", (now - timedelta(hours=10)).isoformat()),
        ]
        conn.executemany(
            """
            INSERT INTO nurse_notes (
                patient_id, note, recorded_by, recorded_at
            )
            VALUES (?, ?, ?, ?)
            """,
            nurse_notes,
        )

        conn.commit()


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {key: row[key] for key in row.keys()}


def _fetch_patient(conn: sqlite3.Connection, patient_id: int) -> sqlite3.Row:
    patient = conn.execute(
        "SELECT * FROM patients WHERE id = ?",
        (patient_id,),
    ).fetchone()
    if patient is None:
        raise NotFoundError(f"Patient {patient_id} not found.")
    return patient


class AuthorizationError(McpError):
    """Raised when the caller is not authorized to execute a tool."""


def _decode_authorization_header(ctx: Context) -> dict[str, Any]:
    cached = ctx.get_state("jwt_claims")
    if cached:
        return cast(dict[str, Any], cached)

    try:
        request = ctx.get_http_request()
    except Exception as exc:  # pragma: no cover - defensive path
        raise AuthorizationError("Authorization requires an HTTP transport.") from exc

    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise AuthorizationError("Missing Authorization: Bearer <token> header.")

    token = auth_header.split(" ", 1)[1].strip()
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except ExpiredSignatureError as exc:
        raise AuthorizationError("JWT token expired.") from exc
    except InvalidTokenError as exc:
        raise AuthorizationError("Invalid JWT token.") from exc

    ctx.set_state("jwt_claims", claims)
    return claims


def authorize(ctx: Context, tool_name: str) -> dict[str, Any]:
    claims = _decode_authorization_header(ctx)
    role = claims.get("role")
    if role is None:
        raise AuthorizationError("Token missing role claim.")

    allowed_roles = TOOL_TO_ROLES.get(tool_name, set())
    if role not in allowed_roles:
        raise AuthorizationError(f"Role '{role}' may not call {tool_name}.")
    return claims


def log_audit(claims: dict[str, Any], tool_name: str, target_id: Any, payload: dict[str, Any] | None = None) -> None:
    body = json.dumps(payload or {}, default=str)
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_log (actor_email, actor_role, tool_name, target_id, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                claims.get("email"),
                claims.get("role"),
                tool_name,
                str(target_id),
                body,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()


server = FastMCP(
    name="Patient Data RBAC MCP",
    instructions=(
        "You are a secure patient-data MCP server. Every tool call is audited and requires a JWT "
        "with the correct hospital role. Follow RBAC strictly and surface clear errors if the "
        "caller is not authorized."
    ),
    version="1.0.0",
)


@server.tool(name="ViewPatientHistory", description="Return demographics, vitals, labs, appointments, nurse notes, and billing for a patient.")
def view_patient_history(patient_id: int, ctx: Context) -> dict[str, Any]:
    authorize(ctx, "ViewPatientHistory")
    with get_connection() as conn:
        patient = _fetch_patient(conn, patient_id)
        vitals = [
            _row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM vitals WHERE patient_id = ? ORDER BY recorded_at DESC",
                (patient_id,),
            ).fetchall()
        ]
        labs = [
            _row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM lab_orders WHERE patient_id = ? ORDER BY ordered_at DESC",
                (patient_id,),
            ).fetchall()
        ]
        appointments = [
            _row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM appointments WHERE patient_id = ? ORDER BY appointment_date DESC",
                (patient_id,),
            ).fetchall()
        ]
        nurse_notes = [
            _row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM nurse_notes WHERE patient_id = ? ORDER BY recorded_at DESC",
                (patient_id,),
            ).fetchall()
        ]
        billing = [
            _row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM billing WHERE patient_id = ?",
                (patient_id,),
            ).fetchall()
        ]

    return {
        "patient": _row_to_dict(patient),
        "vitals": vitals,
        "lab_orders": labs,
        "appointments": appointments,
        "nurse_notes": nurse_notes,
        "billing": billing,
    }


@server.tool(name="UpdateDiagnosis", description="Update the working diagnosis for a patient.")
def update_diagnosis(patient_id: int, diagnosis: str, ctx: Context) -> dict[str, Any]:
    claims = authorize(ctx, "UpdateDiagnosis")

    with get_connection() as conn:
        _fetch_patient(conn, patient_id)
        conn.execute(
            "UPDATE patients SET diagnosis = ? WHERE id = ?",
            (diagnosis.strip(), patient_id),
        )
        conn.commit()

    log_audit(claims, "UpdateDiagnosis", patient_id, {"diagnosis": diagnosis})
    return {"status": "updated", "patient_id": patient_id, "diagnosis": diagnosis}


@server.tool(name="OrderLabTest", description="Create a lab order for the given patient.")
def order_lab_test(patient_id: int, test_name: str, ctx: Context) -> dict[str, Any]:
    claims = authorize(ctx, "OrderLabTest")
    ordered_at = datetime.utcnow().isoformat()

    with get_connection() as conn:
        _fetch_patient(conn, patient_id)
        cursor = conn.execute(
            """
            INSERT INTO lab_orders (
                patient_id, test_name, status, ordered_by, ordered_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (patient_id, test_name.strip(), "ordered", claims.get("email"), ordered_at),
        )
        conn.commit()
        order_id = cursor.lastrowid
        record = conn.execute(
            "SELECT * FROM lab_orders WHERE id = ?",
            (order_id,),
        ).fetchone()

    log_audit(claims, "OrderLabTest", order_id, {"patient_id": patient_id, "test_name": test_name})
    return _row_to_dict(record)


@server.tool(name="UpdateVitals", description="Insert a new vitals row for a patient.")
def update_vitals(patient_id: int, data: VitalUpdate, ctx: Context) -> dict[str, Any]:
    claims = authorize(ctx, "UpdateVitals")
    if not data:
        raise McpError("Vitals payload cannot be empty.")

    allowed_keys = {"blood_pressure", "heart_rate", "temperature", "respiratory_rate", "notes"}
    unknown = set(data.keys()) - allowed_keys
    if unknown:
        raise McpError(f"Unsupported vital keys: {', '.join(sorted(unknown))}")

    with get_connection() as conn:
        _fetch_patient(conn, patient_id)
        recorded_at = datetime.utcnow().isoformat()
        cursor = conn.execute(
            """
            INSERT INTO vitals (
                patient_id, recorded_at, blood_pressure, heart_rate,
                temperature, respiratory_rate, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                patient_id,
                recorded_at,
                data.get("blood_pressure"),
                data.get("heart_rate"),
                data.get("temperature"),
                data.get("respiratory_rate"),
                data.get("notes"),
            ),
        )
        conn.commit()
        vitals_row = conn.execute(
            "SELECT * FROM vitals WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()

    log_audit(claims, "UpdateVitals", patient_id, {"recorded_at": recorded_at, **data})
    return _row_to_dict(vitals_row)


@server.tool(name="RecordNurseNotes", description="Record a nursing note for a patient.")
def record_nurse_notes(patient_id: int, note: str, ctx: Context) -> dict[str, Any]:
    claims = authorize(ctx, "RecordNurseNotes")
    timestamp = datetime.utcnow().isoformat()

    with get_connection() as conn:
        _fetch_patient(conn, patient_id)
        cursor = conn.execute(
            """
            INSERT INTO nurse_notes (patient_id, note, recorded_by, recorded_at)
            VALUES (?, ?, ?, ?)
            """,
            (patient_id, note.strip(), claims.get("email"), timestamp),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM nurse_notes WHERE id = ?", (cursor.lastrowid,)).fetchone()

    log_audit(claims, "RecordNurseNotes", patient_id, {"note": note})
    return _row_to_dict(row)


@server.tool(name="ViewLabOrders", description="List lab orders, optionally filtered by status or patient.")
def view_lab_orders(
    status: str | None = None,
    patient_id: int | None = None,
    ctx: Context | None = None,
) -> list[dict[str, Any]]:
    if ctx is None:
        raise McpError("Context injection failed for ViewLabOrders.")
    authorize(ctx, "ViewLabOrders")
    query = "SELECT * FROM lab_orders"
    params: list[Any] = []
    clauses = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if patient_id:
        clauses.append("patient_id = ?")
        params.append(patient_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY ordered_at DESC"

    with get_connection() as conn:
        rows = [
            _row_to_dict(row)
            for row in conn.execute(
                query,
                params,
            ).fetchall()
        ]
    return rows


@server.tool(name="EnterLabResults", description="Attach a lab result to an existing order.")
def enter_lab_results(lab_order_id: int, result: str, ctx: Context) -> dict[str, Any]:
    claims = authorize(ctx, "EnterLabResults")
    fulfilled_at = datetime.utcnow().isoformat()

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT * FROM lab_orders WHERE id = ?",
            (lab_order_id,),
        ).fetchone()
        if existing is None:
            raise NotFoundError(f"Lab order {lab_order_id} not found.")

        conn.execute(
            """
            UPDATE lab_orders
            SET result = ?, status = ?, result_entered_by = ?, fulfilled_at = ?
            WHERE id = ?
            """,
            (result, "completed", claims.get("email"), fulfilled_at, lab_order_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM lab_orders WHERE id = ?", (lab_order_id,)).fetchone()

    log_audit(claims, "EnterLabResults", lab_order_id, {"result": result})
    return _row_to_dict(updated)


@server.tool(name="ScheduleAppointment", description="Schedule a follow-up appointment for the patient.")
def schedule_appointment(
    patient_id: int,
    date: str,
    reason: str | None = None,
    provider: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    if ctx is None:
        raise McpError("Context injection failed for ScheduleAppointment.")
    claims = authorize(ctx, "ScheduleAppointment")

    try:
        appointment_date = datetime.fromisoformat(date)
    except ValueError as exc:
        raise McpError("date must be ISO-8601 formatted, e.g. 2025-01-15T09:30:00") from exc

    with get_connection() as conn:
        _fetch_patient(conn, patient_id)
        cursor = conn.execute(
            """
            INSERT INTO appointments (
                patient_id, appointment_date, provider, reason, status, scheduled_by
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                patient_id,
                appointment_date.isoformat(),
                provider or "Scheduling Team",
                reason or "Follow-up",
                "scheduled",
                claims.get("email"),
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM appointments WHERE id = ?", (cursor.lastrowid,)).fetchone()

    log_audit(
        claims,
        "ScheduleAppointment",
        patient_id,
        {"appointment_id": cursor.lastrowid, "date": appointment_date.isoformat()},
    )
    return _row_to_dict(row)


@server.tool(name="BillingInfoView", description="Return billing profile for the patient.")
def billing_info_view(patient_id: int, ctx: Context) -> dict[str, Any]:
    authorize(ctx, "BillingInfoView")
    with get_connection() as conn:
        patient = _fetch_patient(conn, patient_id)
        billing = conn.execute(
            "SELECT * FROM billing WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()

    return {
        "patient": _row_to_dict(patient),
        "billing": _row_to_dict(billing),
    }


def issue_token(role: str, email: str, subject: str | None, days_valid: int) -> str:
    payload = {
        "sub": subject or email,
        "role": role,
        "email": email,
        "iss": "patient-access-mcp",
        "exp": datetime.utcnow() + timedelta(days=days_valid),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Patient Data Access MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http", "streamable-http"],
        default=os.getenv("MCP_TRANSPORT", "sse"),
        help="Transport to expose (default: sse).",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", "127.0.0.1"),
        help="Host for HTTP transports.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_PORT", "8000")),
        help="Port for HTTP transports.",
    )
    parser.add_argument(
        "--issue-token",
        choices=sorted(PermissionToolMapping.keys()),
        help="Emit a JWT for the selected role and exit.",
    )
    parser.add_argument("--token-email", help="Email to embed in the issued token.")
    parser.add_argument("--token-subject", help="Subject/identifier for the issued token.")
    parser.add_argument(
        "--token-days",
        type=int,
        default=7,
        help="Validity window (days) for issued tokens (default: 7).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.issue_token:
        email = args.token_email or f"{args.issue_token.lower()}@example.com"
        token = issue_token(args.issue_token, email, args.token_subject, args.token_days)
        print(token)
        return

    transport_kwargs: dict[str, Any] = {}
    if args.transport in {"sse", "http", "streamable-http"}:
        transport_kwargs["host"] = args.host
        transport_kwargs["port"] = args.port

    server.run(transport=args.transport, **transport_kwargs)


init_db()
seed_data()

if __name__ == "__main__":
    main()
