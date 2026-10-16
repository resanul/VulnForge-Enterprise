# VulnForge Enterprise REST API Reference

Interactive OpenAPI documentation is available live at `/docs` (Swagger UI) and `/redoc` (ReDoc).

## Base URL
`/api/v1`

---

## 1. Authentication (`/auth`)

### POST `/auth/login`
- **Request Body**: `{"username": "admin", "password": "..."}`
- **Response**: `{"access_token": "...", "token_type": "bearer", "user_id": 1, "role": "admin"}`

### GET `/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: Current user profile object.

---

## 2. Asset Inventory (`/assets`)

### GET `/assets`
- **Query Params**: `criticality`, `environment`, `search`
- **Response**: Array of registered infrastructure assets.

### POST `/assets`
- **Request Body**: `{"name": "Web-01", "target_value": "192.168.1.10", "criticality": "high", "environment": "production"}`

### POST `/assets/import-csv`
- **Request Body**: `{"csv_content": "name,target_value,criticality,environment\n..."}`

---

## 3. Scan Orchestrator (`/scans`)

### GET `/scans/profiles`
- Returns configured scan profiles.

### POST `/scans/launch`
- **Request Body**: `{"title": "DMZ Audit", "target": "192.168.1.50", "profile_id": 1, "credential_id": null}`
- **Behavior**: Backend verifies target against approved scopes before enqueueing.

### GET `/scans/jobs/{id}`
- Returns real-time execution progress, status (`pending`, `running`, `completed`, `failed`), and logs.

### POST `/scans/jobs/{id}/cancel`
- Cancels an in-progress scan job.

---

## 4. Vulnerabilities (`/findings`)

### GET `/findings`
- **Query Params**: `severity`, `status`, `cve`, `asset_id`, `limit`
- **Response**: Unified normalized findings array.

### POST `/findings/{id}/status`
- **Request Body**: `{"status": "Suppressed", "justification": "Compensating firewall rule active", "expires_at": 1799999999}`

---

## 5. Reports (`/reports`)

### POST `/reports/generate`
- **Request Body**: `{"job_id": 1, "report_format": "html|json|csv|pdf", "report_type": "technical"}`

### GET `/reports/download/{id}`
- Streams the generated file with correct MIME type.
