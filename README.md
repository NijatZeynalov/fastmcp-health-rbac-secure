# Patient Data Access MCP

FastMCP server + Gemini 2.0 Flash LangChain client showcasing RBAC-protected patient data tools backed by SQLite + JWT.

## Prerequisites

* Python 3.11+
* `GOOGLE_API_KEY` for Gemini 2.0 Flash (already referenced inside `.env`)

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Environment Variables

`.env` ships with sample values:

* `JWT_SECRET` – symmetric key used to validate tokens.
* `DB_URL` – path to the SQLite file (`sqlite:///app.db` by default).
* `MCP_SERVER_SSE_URL` – SSE endpoint exposed by FastMCP (`http://127.0.0.1:8000/sse`).
* `GOOGLE_API_KEY` – Gemini credential (replace with a valid key).
* `JWT_*` – pre-generated tokens scoped to Doctor, Nurse, LabTechnician, and Admin roles.

Update secrets before using in a real setting.

## Running the MCP Server

```powershell
python server.py --transport sse --host 127.0.0.1 --port 8000
```

* The first launch creates/ seeds `app.db` with staff, patients, vitals, labs, etc.
* Other transports are available (`stdio`, `http`, `streamable-http`). Pass `--transport stdio` to embed inside another process.
* Use `python server.py --issue-token Doctor --token-email someone@hospital.test` to mint new JWTs.

## LangChain + Gemini Client

The client connects to the MCP server through the LangChain MCP Adapter and lets Gemini pick the correct MCP tool per request.

```powershell
python langchain_client.py --role doctor --query "Order a lipid panel for patient 2"
```

Flags:

* `--role` – one of `doctor|nurse|labtechnician|adminstaff` (selects the JWT token).
* `--query` – natural-language instruction for Gemini.
* `--server-url` – override the SSE endpoint if the server runs elsewhere.

## RBAC Map ↔ Tools

| Role           | Tools                                                                 |
|----------------|-----------------------------------------------------------------------|
| Doctor         | `ViewPatientHistory`, `UpdateDiagnosis`, `OrderLabTest`               |
| Nurse          | `ViewPatientHistory`, `UpdateVitals`, `RecordNurseNotes`              |
| LabTechnician  | `ViewLabOrders`, `EnterLabResults`                                    |
| AdminStaff     | `ScheduleAppointment`, `BillingInfoView`                              |

Every write tool automatically records an audit entry in the `audit_log` table (`who`, `what`, `when`, payload).
