# SIEM Data Normalization — Logon & Device Schemas
## Reference Design for Risk Assessment & AI Classification Pipeline

> **Project:** SIEM Data Risk Assessment and Security Events Classification with AI and Prompt Engineering  
> **Phase:** Data Normalization & Standardization  
> **Scope:** `logon.csv` and `device.csv` schemas, JSON schemas, and full attribute mapping tables

---

## Table of Contents

1. [Standards Crosswalk]
2. [Schema Design Principles]
3. [LOGON Schema]
   - 3.1 Attribute Catalog
   - 3.2 Full JSON Schema
   - 3.3 Sample Normalized Record
   - 3.4 Attribute Mapping Tables
4. [DEVICE Schema]
   - 5.1 Attribute Catalog
   - 5.2 Full JSON Schema
   - 5.3 Sample Normalized Record
   - 5.4 Attribute Mapping Tables
5. [Shared / Common Envelope Fields]
6. [Enumeration Master Lists]
7. [AI Pipeline Readiness Notes]

---

## 1. Standards Crosswalk

The schema design below synthesizes the following industry standards. Each attribute references which standards informed it.

| Standard | Abbreviation | Coverage Area |
|---|---|---|
| [Microsoft ASIM Authentication Schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication) | **ASIM** | Authentication/Logon events, mandatory/recommended/optional field classes |
| [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs) | **ECS** | Universal field naming, event categorization, host/user objects |
| [OSSEM Common Data Model — logon entity](https://ossemproject.com/cdm/entities/logon.html) | **OSSEM** | Logon-specific fields, Windows event alignment |
| [OSSEM Common Data Model — device entity](https://ossemproject.com/cdm/entities/device.html) | **OSSEM** | Device/host fields, MAC, OS, interface details |
| [Google Chronicle / UDM](https://docs.cloud.google.com/chronicle/docs/reference/important-udm-fields) | **UDM** | principal/target/metadata structure, event_type enums (USER_LOGIN, USER_LOGOUT) |
| [AWS Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) | **ASFF** | Finding severity, confidence, criticality scoring |
| [NXLog LEEF](https://docs.nxlog.co/integrate/leef.html) | **LEEF** | Syslog-style flat field naming alternatives |
| [Sigma Detection Format](https://sigmahq.io/docs/basics/rules.html) | **Sigma** | Detection-friendly field naming, logsource category alignment |

---

## 2. Schema Design Principles

### 2.1 Field Class Hierarchy (ASIM-aligned)

| Class | Meaning |
|---|---|
| **REQUIRED** | Must be present in every normalized record. If the source doesn't provide it, derive it or use a sentinel null value. |
| **RECOMMENDED** | Normalize when available; leave `null` when unavailable. AI prompts should account for absence. |
| **OPTIONAL** | Enrich if available. Useful for scoring but not blocking. |
| **DERIVED** | Computed at normalization time from other fields (e.g., `event_duration`, `is_after_hours`). |

### 2.2 Naming Convention

- **snake_case** for all field names (ECS, OSSEM standard)
- Prefixes: `event_`, `user_`, `src_`, `dst_`, `dvc_`, `logon_`, `device_` used to namespace collisions
- All timestamps: **ISO 8601 UTC** (`2010-01-02T07:04:00Z`)
- Enumerations: **SCREAMING_SNAKE_CASE** for values (e.g., `LOGON`, `LOGOFF`, `CONNECT`)
- Boolean flags: `true` / `false` (JSON boolean, never string)

### 2.3 ID Strategy

Each normalized record carries three IDs:
- `event_uid` — the normalized unique event ID (derived from source `id` with prefix stripping)
- `event_original_uid` — the raw source `id` preserved verbatim
- `session_id` — optional, links logon/logoff pairs (null if not derivable)

---

## 3. LOGON Schema

### 3.1 Attribute Catalog

#### GROUP A — Event Identity (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `event_uid` | REQUIRED | string | Normalized unique event identifier. Derived from source `id` with `{}` stripped. | `id` (cleaned) | ASIM `EventUid`, ECS `event.id`, UDM `metadata.id` |
| `event_original_uid` | REQUIRED | string | Raw source event ID, preserved verbatim for traceability. | `id` | ASIM `EventOriginalUid` |
| `event_schema` | REQUIRED | string (enum) | Always `"LOGON"` for this table. Identifies the schema context. | — (hardcoded) | ASIM `EventSchema` |
| `event_schema_version` | REQUIRED | string | Schema version for forward-compatibility. Semantic versioning. | — (hardcoded) | ASIM `EventSchemaVersion` |

---

#### GROUP B — Temporal (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `event_timestamp` | REQUIRED | ISO 8601 UTC string | Canonical normalized timestamp of when the event occurred. | `date` (converted) | ASIM `EventStartTime`, ECS `@timestamp`, UDM `metadata.event_timestamp` |
| `event_timestamp_raw` | RECOMMENDED | string | Original timestamp string as it appeared in the source. | `date` | Traceability |
| `event_duration_seconds` | DERIVED | integer / null | Duration in seconds between a paired Logon and Logoff. Requires session correlation. | Derived | ASIM session correlation |
| `is_after_hours` | DERIVED | boolean | `true` if event_timestamp is outside 07:00–19:00 local business hours. | Derived | Risk scoring |
| `is_weekend` | DERIVED | boolean | `true` if event_timestamp falls on Saturday or Sunday. | Derived | Risk scoring |

---

#### GROUP C — Event Classification (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `event_type` | REQUIRED | string (enum) | High-level category. Always `"AUTHENTICATION"` for this schema. | — (hardcoded) | ECS `event.type`, ASIM `EventType` |
| `event_action` | REQUIRED | string (enum) | The specific action performed. See mapping section. | `activity` | ECS `event.action`, UDM `metadata.event_type` |
| `event_outcome` | REQUIRED | string (enum) | Result of the action: `SUCCESS`, `FAILURE`, `UNKNOWN`. | `activity` + context | ASIM `EventResult`, ECS `event.outcome` |
| `event_result_details` | RECOMMENDED | string (enum) / null | Detailed reason for outcome. Especially for failures. | — | ASIM `EventResultDetails` |
| `event_severity` | RECOMMENDED | string (enum) | Normalized severity: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. | Derived | ASIM `EventSeverity`, ECS `event.severity`, ASFF `Severity.Label` |

---

#### GROUP D — User / Actor (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `user_id` | REQUIRED | string | The user account identifier (employee ID, SAM name, UPN, etc.). | `user` | ASIM `TargetUserId`, ECS `user.id`, OSSEM `user_id` |
| `user_name` | REQUIRED | string | Human-readable username. Same as `user_id` when no display name available. | `user` | ASIM `TargetUsername`, ECS `user.name`, UDM `target.user.userid` |
| `user_type` | OPTIONAL | string (enum) / null | Account type: `REGULAR`, `MACHINE`, `SERVICE_ACCOUNT`, `ADMIN`, `GUEST`, `SYSTEM`. | — | ASIM `TargetUserType`, ECS `user.roles` |
| `user_session_id` | OPTIONAL | string / null | Logon session identifier (hex or GUID) to correlate logon/logoff pairs. | — | OSSEM `logon_id`, ASIM session linking |
| `actor_user_id` | OPTIONAL | string / null | If different from target user — the account initiating auth on behalf of another. | — | ASIM `ActorUserId` |
| `actor_user_name` | OPTIONAL | string / null | Display name of the actor if different from target user. | — | ASIM `ActorUsername` |

---

#### GROUP E — Source Device / Workstation (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `src_hostname` | REQUIRED | string | Hostname of the machine from which the logon was initiated. (=dst_hostname for non-remote logon)| `pc` | ASIM `SrcHostname`, ECS `source.address`, UDM `principal.hostname` |
| `src_ip` | RECOMMENDED | string / null | IP address of source machine. Not in source CSV — enrich from asset DB. | — | ASIM `SrcIpAddr`, ECS `source.ip`, UDM `principal.ip` |
| `src_mac` | OPTIONAL | string / null | MAC address of source machine. | — | OSSEM `dvc_mac_addr`, ECS `host.mac` |
| `src_domain` | OPTIONAL | string / null | Domain of the source machine. | — | ASIM `SrcDomain`, ECS `host.domain` |
| `src_os` | OPTIONAL | string / null | Operating system of source machine (e.g., `"Windows 10"`). | — | OSSEM `dvc_os`, ECS `host.os.name` |
| `src_os_version` | OPTIONAL | string / null | OS version string. | — | OSSEM `dvc_os`, ECS `host.os.version` |

---

#### GROUP F — Target / Destination System (RECOMMENDED)
 
| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `dst_hostname` | REQUIRED | string | Hostname of the system being authenticated to. May equal `src_hostname` for local logons. | — | ASIM `TargetHostname`, UDM `target.hostname` |
| `dst_ip` | OPTIONAL | string / null | IP of target system. | — | ASIM `DvcIpAddr`, UDM `target.ip` |
| `dst_domain` | OPTIONAL | string / null | Domain of target system. | — | ASIM `TargetDomain` |
 
---

#### GROUP G — Authentication Protocol & Method (OPTIONAL)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `logon_protocol` | OPTIONAL | string / null | Auth protocol used: `NTLM`, `KERBEROS`, `LDAP`, `OAUTH`, `SAML`, `RADIUS`. | — | ASIM `LogonProtocol`, OSSEM `logon_authentication_package_name` |
| `logon_method` | OPTIONAL | string / null | Auth method: `PASSWORD`, `MFA`, `CERTIFICATE`, `SSO`, `BIOMETRIC`, `TOKEN`. | — | ASIM `LogonMethod` |

---

#### GROUP H — Risk & Enrichment (DERIVED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `risk_score` | DERIVED | float (0.0–10.0) | Composite risk score assigned by the AI/rule layer. | Derived | ASFF `Criticality`, ASIM `EventSeverity` |
| `risk_factors` | DERIVED | array of strings | Human-readable list of risk indicators (e.g., `["after_hours", "new_pc"]`). | Derived | — |
| `is_new_device_for_user` | DERIVED | boolean | True if this `user_id` has not been seen on this `src_hostname` recently. | Derived | Behavioral |
| `concurrent_session_count` | DERIVED | integer / null | Number of active sessions for this user at the event timestamp. | Derived | Behavioral |
| `failed_logon_count_1h` | DERIVED | integer / null | Count of failed logons for this user in the past 1 hour. | Derived | Brute-force detection |
| `logon_frequency_deviation` | DERIVED | float / null | Z-score of this logon against user's historical logon frequency. | Derived | Anomaly detection |
 
--- 

#### GROUP I — Metadata & Pipeline (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `source_file` | REQUIRED | string | Source file name this record was read from. | — (pipeline) | Traceability |
| `source_line_number` | OPTIONAL | integer | Line number in source CSV. | — (pipeline) | Traceability |
| `additional_fields` | OPTIONAL | object / null | Free-form bag for any source fields not mappable to the schema. | — | ASIM `AdditionalFields`, UDM `additional` |

---

### 3.2 Full JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "siem/logon/v1.0.0",
  "title": "SIEM Normalized Logon Event",
  "description": "Normalized schema for authentication (logon/logoff) events. Aligned with ASIM Authentication v0.1.4, ECS 8.x, OSSEM CDM, Google UDM USER_LOGIN/USER_LOGOUT.",
  "type": "object",

  "required": [
    "event_uid",
    "event_original_uid",
    "event_schema",
    "event_schema_version",
    "event_timestamp",
    "event_type",
    "event_action",
    "event_outcome",
    "user_id",
    "user_name",
    "src_hostname",
    "dst_hostname",
    "source_file",
  ],

  "properties": {

    "event_uid":               { "type": "string", "description": "Normalized unique event ID (source ID cleaned)." },
    "event_original_uid":      { "type": "string", "description": "Raw source event ID verbatim." },
    "event_schema":            { "type": "string", "const": "LOGON" },
    "event_schema_version":    { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$", "example": "1.0.0" },

    "event_timestamp":         { "type": "string", "format": "date-time", "description": "ISO 8601 UTC canonical timestamp." },
    "event_timestamp_raw":     { "type": ["string", "null"] },
    "event_duration_seconds":  { "type": ["integer", "null"], "minimum": 0 },
    "is_after_hours":          { "type": ["boolean", "null"] },
    "is_weekend":              { "type": ["boolean", "null"] },

    "event_type":              { "type": "string", "const": "AUTHENTICATION" },
    "event_action":            {
      "type": "string",
      "enum": ["LOGON", "LOGOFF", "FAILED_LOGON", "ELEVATE", "SESSION_LOCK", "SESSION_UNLOCK", "RECONNECT", "DISCONNECT", "UNKNOWN"],
      "description": "Specific normalized action performed."
    },
    "event_outcome":           { "type": "string", "enum": ["SUCCESS", "FAILURE", "UNKNOWN"] },
    "event_result_details":    {
      "type": ["string", "null"],
      "enum": [
        "NO_SUCH_USER", "INCORRECT_PASSWORD", "ACCOUNT_EXPIRED",
        "PASSWORD_EXPIRED", "USER_LOCKED", "USER_DISABLED",
        "POLICY_VIOLATION", "SESSION_EXPIRED", "INCORRECT_KEY",
        "MFA_REQUIRED", "OTHER", null
      ]
    },
    "event_severity":          { "type": ["string", "null"], "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", null] },

    "user_id":                 { "type": "string" },
    "user_name":               { "type": "string" },
    "user_type":               {
      "type": ["string", "null"],
      "enum": ["REGULAR", "MACHINE", "SERVICE_ACCOUNT", "ADMIN", "GUEST", "SYSTEM", "UNKNOWN", null]
    },
    "user_session_id":         { "type": ["string", "null"] },
    "actor_user_id":           { "type": ["string", "null"] },
    "actor_user_name":         { "type": ["string", "null"] },

    "src_hostname":            { "type": "string" },
    "src_ip":                  { "type": ["string", "null"], "oneOf": [{ "format": "ipv4" }, { "format": "ipv6" }, { "type": "null" }] },
    "src_mac":                 { "type": ["string", "null"], "pattern": "^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$" },
    "src_domain":              { "type": ["string", "null"] },
    "src_os":                  { "type": ["string", "null"] },
    "src_os_version":          { "type": ["string", "null"] },

    "dst_hostname":            { "type": ["string", "null"] },
    "dst_ip":                  { "type": ["string", "null"] },
    "dst_domain":              { "type": ["string", "null"] },

    "logon_protocol":          {
      "type": ["string", "null"],
      "enum": ["NTLM", "KERBEROS", "LDAP", "OAUTH2", "SAML", "RADIUS", "NEGOTIATE", "LOCAL", "UNKNOWN", null]
    },
    "logon_method":            {
      "type": ["string", "null"],
      "enum": ["PASSWORD", "MFA", "CERTIFICATE", "SSO", "BIOMETRIC", "TOKEN", "SMARTCARD", "PASSWORDLESS", "OTHER", null]
    },

    "risk_score":              { "type": ["number", "null"], "minimum": 0.0, "maximum": 10.0 },
    "risk_factors":            { "type": ["array", "null"], "items": { "type": "string" } },
    "is_new_device_for_user":  { "type": ["boolean", "null"] },
    "concurrent_session_count":{ "type": ["integer", "null"], "minimum": 0 },
    "failed_logon_count_1h":   { "type": ["integer", "null"], "minimum": 0 },
    "logon_frequency_deviation":{ "type": ["number", "null"] },

    "source_file":             { "type": "string" },
    "source_line_number":      { "type": ["integer", "null"], "minimum": 1 },
    "additional_fields":       { "type": ["object", "null"] }
  },

  "additionalProperties": false
}
```

---

### 3.3 Sample Normalized Record

Source row: `{F7RX0-K0FN01QO-2580USIE},01/02/2010 07:04:00,NGF0157,PC-6056,Logon`

```json
{
  "event_uid":               "F7RX0-K0FN01QO-2580USIE",
  "event_original_uid":      "{F7RX0-K0FN01QO-2580USIE}",
  "event_schema":            "LOGON",
  "event_schema_version":    "1.0.0",

  "event_timestamp":         "2010-01-02T07:04:00Z",
  "event_timestamp_raw":     "01/02/2010 07:04:00",
  "event_duration_seconds":  null,
  "is_after_hours":          false,
  "is_weekend":              false,

  "event_type":              "AUTHENTICATION",
  "event_action":            "LOGON",
  "event_outcome":           "SUCCESS",
  "event_result_details":    null,
  "event_severity":          "INFORMATIONAL",

  "user_id":                 "NGF0157",
  "user_name":               "NGF0157",
  "user_type":               "REGULAR",
  "user_session_id":         null,
  "actor_user_id":           null,
  "actor_user_name":         null,

  "src_hostname":            "PC-6056",
  "src_ip":                  null,
  "src_mac":                 null,
  "src_domain":              null,
  "src_os":                  null,
  "src_os_version":          null,

  "logon_protocol":          null,
  "logon_method":            null,

  "risk_score":              null,
  "risk_factors":            [],
  "is_new_device_for_user":  null,
  "concurrent_session_count": null,
  "failed_logon_count_1h":   null,
  "logon_frequency_deviation": null,

  "source_file":             "login.csv",
  "source_line_number":      2,
  "additional_fields":       null
}
```

---

### 3.4 Attribute Mapping Tables

#### Mapping: `event_action` (from source `activity`)

This is the most critical mapping. The source `activity` field must be mapped before any other processing. Note: the source only contains `Logon` and `Logoff`, but the mapping table covers all realistic variants a future data source could produce.

| Canonical Value | Source Variants | Description | UDM Equivalent | ASIM Equivalent | ECS `event.action` |
|---|---|---|---|---|---|
| `LOGON` | `Logon`, `Login`, `log on`, `log_on`, `Sign In`, `sign_in`, `signin`, `Authenticated`, `authentication_success`, `4624`, `user_login`, `USER_LOGGED_IN`, `connect`, `connected`, `Session opened`, `start_session` | Successful authentication and session start | `USER_LOGIN` | `Logon` | `logged-in` |
| `LOGOFF` | `Logoff`, `Logout`, `log off`, `log_off`, `Sign Out`, `sign_out`, `signout`, `4634`, `4647`, `user_logout`, `USER_LOGGED_OUT`, `Session closed`, `end_session`, `Disconnected`, `session_end` | Session termination | `USER_LOGOUT` | `Logoff` | `logged-out` |
| `FAILED_LOGON` | `Failed Logon`, `failed_login`, `Login Failed`, `authentication_failed`, `4625`, `LOGON_FAILURE`, `auth_failure`, `Invalid Password`, `Bad password` | Authentication attempt that did not succeed | `USER_LOGIN` + `FAILURE` outcome | `Logon` + `EventResult=Failure` | `authentication-failure` |
| `ELEVATE` | `Elevate`, `Run as Admin`, `runas`, `sudo`, `privilege_escalation`, `4648`, `UAC prompt accepted` | Privilege elevation / impersonation | `USER_UNCATEGORIZED` | `Elevate` | `escalated` |
| `SESSION_LOCK` | `Lock`, `Locked`, `screen_lock`, `4800`, `session_locked` | Workstation lock | `USER_UNCATEGORIZED` | — | `locked` |
| `SESSION_UNLOCK` | `Unlock`, `Unlocked`, `screen_unlock`, `4801`, `session_unlocked` | Workstation unlock | `USER_LOGIN` | `Logon` (type=Unlock) | `unlocked` |
| `RECONNECT` | `Reconnect`, `reconnected`, `4778`, `session_reconnect`, `RDP reconnect` | Reconnect to an existing session | `USER_LOGIN` | `Logon` (type=RemoteInteractive) | `reconnected` |
| `DISCONNECT` | `Disconnect`, `disconnected`, `4779`, `session_disconnect`, `Remote disconnect` | Disconnect from session without logoff | `USER_LOGOUT` | `Logoff` | `disconnected` |
| `UNKNOWN` | Any value not matched above | Fallback for unrecognized activity values | `USER_UNCATEGORIZED` | — | `unknown` |

---

#### Mapping: `event_outcome` (derived from `event_action`)

| `event_action` | `event_outcome` | Reasoning |
|---|---|---|
| `LOGON` | `SUCCESS` | A logon record implies the authentication succeeded |
| `LOGOFF` | `SUCCESS` | A logoff record is a successful graceful session end |
| `FAILED_LOGON` | `FAILURE` | Explicit failure indicator |
| `ELEVATE` | `SUCCESS` or `FAILURE` | Needs context; default `SUCCESS` if not specified |
| `SESSION_LOCK` | `SUCCESS` | Operational event, not an auth outcome |
| `SESSION_UNLOCK` | `SUCCESS` | Assumes successful unlock |
| `RECONNECT` | `SUCCESS` | Successful reconnect |
| `DISCONNECT` | `SUCCESS` | Operational disconnect |
| `UNKNOWN` | `UNKNOWN` | Cannot determine |

---

#### Mapping: `event_severity` (derived rule)

Since the source data has no explicit severity, severity is derived from context (event_duration_seconds, ,is_after_hours,is_weekend, event_outcome,user_id, user_type, actor_user_id, src_hostname, is_new_device_for_user, concurrent_session_count, failed_logon_count_1h, logon_frequency_deviation ...):

| Condition | Severity |
|---|---|
| Normal business hours logon, known PC | `INFORMATIONAL` |
| Logon on weekend | `LOW` |
| Logon after midnight / before 05:00 | `MEDIUM` |
| Failed logon | `MEDIUM` |
| Multiple failed logons (≥3 in 1h) | `HIGH` |
| Logon from new/unknown PC | `MEDIUM` |
| Logon from new PC + after hours | `HIGH` |
| Concurrent active sessions (≥3) | `HIGH` |
| ELEVATE event | `MEDIUM` |
| Any CRITICAL rule match | `CRITICAL` |

---

#### Mapping: `user_type` (inferred from `user_id` pattern)

| Canonical Value | Detection Heuristic |
|---|---|
| `REGULAR` | Standard alphanumeric employee ID (e.g., `NGF0157`) |
| `SERVICE_ACCOUNT` | Contains `svc`, `_svc`, `service`, `srv`, `$` suffix (Windows machine accounts) |
| `MACHINE` | Ends in `$` (Windows computer accounts) |
| `ADMIN` | Contains `admin`, `adm`, or maps to known privileged account list |
| `SYSTEM` | Equals `SYSTEM`, `LocalSystem`, `NT AUTHORITY\SYSTEM` |
| `GUEST` | Equals `Guest`, `GUEST`, `visitor` |
| `UNKNOWN` | No pattern match |

---

## 4. DEVICE Schema

### 4.1 Attribute Catalog

#### GROUP A — Event Identity (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `event_uid` | REQUIRED | string | Normalized unique event ID. For device CSV: strip `{}`, retain `DV-XXXX-` prefix. | `id` (cleaned) | ASIM `EventUid`, ECS `event.id` |
| `event_original_uid` | REQUIRED | string | Raw source event ID verbatim. | `id` | ASIM `EventOriginalUid` |
| `event_schema` | REQUIRED | string (enum) | Always `"DEVICE"` for this table. | — (hardcoded) | ASIM `EventSchema` |
| `event_schema_version` | REQUIRED | string | Semantic version. | — (hardcoded) | ASIM `EventSchemaVersion` |

---

#### GROUP B — Temporal (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `event_timestamp` | REQUIRED | ISO 8601 UTC string | Normalized timestamp. Source has seconds-level precision for most rows. | `date` (converted) | ASIM, ECS, UDM |
| `event_timestamp_raw` | RECOMMENDED | string | Raw source timestamp. | `date` | Traceability |
| `event_duration_seconds` | DERIVED | integer / null | Time between paired Connect/Disconnect events. Requires session correlation. | Derived | — |
| `is_after_hours` | DERIVED | boolean | Outside 07:00–19:00 business hours. | Derived | Risk |
| `is_weekend` | DERIVED | boolean | Saturday or Sunday. | Derived | Risk |

---

#### GROUP C — Event Classification (REQUIRED)

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `event_type` | REQUIRED | string (enum) | High-level category: `"DEVICE_ACTIVITY"` | — (hardcoded) | ECS `event.type` |
| `event_action` | REQUIRED | string (enum) | Specific action: `CONNECT`, `DISCONNECT`, `INSTALL`, `UNINSTALL`, `MOUNT`, `UNMOUNT`, `BLOCKED`, `UNKNOWN`. | `activity` | ECS `event.action`, ASIM `EventType` |
| `event_outcome` | REQUIRED | string (enum) | `SUCCESS`, `FAILURE`, `UNKNOWN` | Derived | ASIM `EventResult`, ECS `event.outcome` |
| `event_severity` | RECOMMENDED | string (enum) / null | Normalized severity. | Derived | ASIM `EventSeverity` |
| `event_result_details` | OPTIONAL | string / null | Why blocked or failed (if applicable). | — | ASIM `EventResultDetails` |

---

#### GROUP D — Device Under Action (REQUIRED/RECOMMENDED)

These fields describe the **peripheral device** being connected or disconnected — NOT the workstation.

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `device_id` | RECOMMENDED | string / null | Unique identifier for the peripheral device (serial number, GUID, VID:PID). | — | OSSEM `dvc_interface_guid`, ECS `device.id` |
| `device_type` | RECOMMENDED | string (enum) / null | Type of peripheral: `USB_STORAGE`, `USB_HID`, `USB_PRINTER`, `BLUETOOTH`, `THUNDERBOLT`, `NETWORK_ADAPTER`, `CD_DVD`, `UNKNOWN`. | — | OSSEM `dvc_type`, ASIM DeviceType |
| `device_name` | OPTIONAL | string / null | Friendly name or label of the device. | — | OSSEM `dvc_model_name`, ECS `device.name` |
| `device_vid` | OPTIONAL | string / null | USB Vendor ID (4-digit hex). | — | Windows Device Manager |
| `device_pid` | OPTIONAL | string / null | USB Product ID (4-digit hex). | — | Windows Device Manager |
| `device_class` | OPTIONAL | string / null | Windows device class GUID or class name. | — | Windows WMI |
| `device_capacity_bytes` | OPTIONAL | integer / null | Storage capacity in bytes (for storage devices). | — | Risk scoring |

---

#### GROUP E — Host Workstation (REQUIRED)

The workstation where the device event occurred.

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `host_hostname` | REQUIRED | string | Hostname of the workstation where event occurred. | `pc` | OSSEM `dvc_hostname`, ECS `host.name`, UDM `principal.hostname` |
| `host_ip` | RECOMMENDED | string / null | IP of workstation. | — | OSSEM `dvc_ip_addr`, ECS `host.ip` |
| `host_mac` | OPTIONAL | string / null | MAC address of the workstation's NIC. | — | OSSEM `dvc_mac_addr`, ECS `host.mac` |
| `host_domain` | OPTIONAL | string / null | Domain/realm. | — | OSSEM `dvc_domain`, ECS `host.domain` |
| `host_os` | OPTIONAL | string / null | OS name. | — | OSSEM `dvc_os`, ECS `host.os.name` |

---

#### GROUP F — User (REQUIRED)

The user logged in at the workstation at the time of the device event.

| Attribute | Class | Type | Description | Source Field | Standards |
|---|---|---|---|---|---|
| `user_id` | REQUIRED | string | User account ID at the workstation at time of device event. | `user` | OSSEM `user_id`, ECS `user.id`, UDM `principal.user.userid` |
| `user_name` | REQUIRED | string | Human-readable user name.Same as `user_id` when no display name available. | `user` | OSSEM `user_name`, ECS `user.name` |
| `user_type` | OPTIONAL | string (enum) / null | Account type (same enum as logon schema). | — | — |

---

#### GROUP H — Risk & Enrichment (DERIVED)

| Attribute | Class | Type | Description |
|---|---|---|---|
| `risk_score` | DERIVED | float (0.0–10.0) | AI-assigned composite risk. |
| `risk_factors` | DERIVED | array of strings | List of triggered risk rules. |
| `is_storage_device` | DERIVED | boolean | True if `device_type` is USB_STORAGE, CD_DVD, or similar. |
| `is_authorized_device` | DERIVED | boolean / null | True if device_id is on an approved whitelist. |
| `is_new_device_for_user` | DERIVED | boolean / null | True if this user has never connected this device before. |
| `is_new_device_for_host` | DERIVED | boolean / null | True if this device has never been connected to this host before. |
| `session_duration_seconds` | DERIVED | integer / null | Duration of the connect/disconnect pair. |
| `device_connection_count_1h` | DERIVED | integer / null | How many times this user has connected a device in the past 1h. |
| `concurrent_device_count` | DERIVED | integer / null | Number of devices currently connected by this user at this host. |
| `logon_event_uid` | DERIVED | string / null | Links to the correlated logon event (for session binding). |

---

#### GROUP I — Metadata & Pipeline (REQUIRED)

| Attribute | Class | Type | Description |
|---|---|---|---|
| `source_file` | REQUIRED | string | Source CSV file name. |
| `source_line_number` | OPTIONAL | integer | Source row number. |
| `additional_fields` | OPTIONAL | object / null | Raw unmapped source fields. |

---

### 4.2 Full JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "siem/device/v1.0.0",
  "title": "SIEM Normalized Device Event",
  "description": "Normalized schema for peripheral device connect/disconnect events. Aligned with OSSEM Device CDM, ECS 8.x host/device fields, ASIM, and Google UDM.",
  "type": "object",

  "required": [
    "event_uid",
    "event_original_uid",
    "event_schema",
    "event_schema_version",
    "event_timestamp",
    "event_type",
    "event_action",
    "event_outcome",
    "host_hostname",
    "user_id",
    "user_name",
    "source_file",
  ],

  "properties": {

    "event_uid":               { "type": "string" },
    "event_original_uid":      { "type": "string" },
    "event_schema":            { "type": "string", "const": "DEVICE" },
    "event_schema_version":    { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },

    "event_timestamp":         { "type": "string", "format": "date-time" },
    "event_timestamp_raw":     { "type": ["string", "null"] },
    "event_duration_seconds":  { "type": ["integer", "null"], "minimum": 0 },
    "is_after_hours":          { "type": ["boolean", "null"] },
    "is_weekend":              { "type": ["boolean", "null"] },

    "event_type":              { "type": "string", "const": "DEVICE_ACTIVITY" },
    "event_action":            {
      "type": "string",
      "enum": ["CONNECT", "DISCONNECT", "INSTALL", "UNINSTALL", "MOUNT", "UNMOUNT", "BLOCKED", "UNKNOWN"]
    },
    "event_outcome":           { "type": "string", "enum": ["SUCCESS", "FAILURE", "UNKNOWN"] },
    "event_severity":          { "type": ["string", "null"], "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", null] },
    "event_result_details":    { "type": ["string", "null"] },

    "device_id":               { "type": ["string", "null"] },
    "device_type":             {
      "type": ["string", "null"],
      "enum": ["USB_STORAGE", "USB_HID", "USB_PRINTER", "USB_AUDIO", "BLUETOOTH", "THUNDERBOLT", "NETWORK_ADAPTER", "CD_DVD", "SMARTCARD_READER", "BIOMETRIC", "UNKNOWN", null]
    },
    "device_name":             { "type": ["string", "null"] },
    "device_vid":              { "type": ["string", "null"], "pattern": "^[0-9A-Fa-f]{4}$" },
    "device_pid":              { "type": ["string", "null"], "pattern": "^[0-9A-Fa-f]{4}$" },
    "device_class":            { "type": ["string", "null"] },
    "device_capacity_bytes":   { "type": ["integer", "null"], "minimum": 0 },

    "host_hostname":           { "type": "string" },
    "host_ip":                 { "type": ["string", "null"] },
    "host_mac":                { "type": ["string", "null"] },
    "host_domain":             { "type": ["string", "null"] },
    "host_os":                 { "type": ["string", "null"] },

    "user_id":                 { "type": "string" },
    "user_name":               { "type": "string" },
    "user_type":               {
      "type": ["string", "null"],
      "enum": ["REGULAR", "MACHINE", "SERVICE_ACCOUNT", "ADMIN", "GUEST", "SYSTEM", "UNKNOWN", null]
    },

    "risk_score":              { "type": ["number", "null"], "minimum": 0.0, "maximum": 10.0 },
    "risk_factors":            { "type": ["array", "null"], "items": { "type": "string" } },
    "is_storage_device":       { "type": ["boolean", "null"] },
    "is_authorized_device":    { "type": ["boolean", "null"] },
    "is_new_device_for_user":  { "type": ["boolean", "null"] },
    "is_new_device_for_host":  { "type": ["boolean", "null"] },
    "session_duration_seconds":{ "type": ["integer", "null"], "minimum": 0 },
    "device_connection_count_1h": { "type": ["integer", "null"], "minimum": 0 },
    "concurrent_device_count": { "type": ["integer", "null"], "minimum": 0 },
    "logon_event_uid":         { "type": ["string", "null"] },

    "source_file":             { "type": "string" },
    "source_line_number":      { "type": ["integer", "null"] },
    "additional_fields":       { "type": ["object", "null"] }
  },

  "additionalProperties": false
}
```

---

### 4.3 Sample Normalized Record

Source row: `{DV-0121-WQGOTZ7OZ3NK},01/04/2010 08:05:00,IKP0472,PC-3842,Connect`

```json
{
  "event_uid":               "DV-0121-WQGOTZ7OZ3NK",
  "event_original_uid":      "{DV-0121-WQGOTZ7OZ3NK}",
  "event_schema":            "DEVICE",
  "event_schema_version":    "1.0.0",

  "event_timestamp":         "2010-01-04T08:05:00Z",
  "event_timestamp_raw":     "01/04/2010 08:05:00",
  "event_duration_seconds":  null,
  "is_after_hours":          false,
  "is_weekend":              false,

  "event_type":              "DEVICE_ACTIVITY",
  "event_action":            "CONNECT",
  "event_outcome":           "SUCCESS",
  "event_severity":          "INFORMATIONAL",
  "event_result_details":    null,

  "device_id":               null,
  "device_type":             "UNKNOWN",
  "device_name":             null,
  "device_vid":              null,
  "device_pid":              null,
  "device_class":            null,
  "device_capacity_bytes":   null,

  "host_hostname":           "PC-3842",
  "host_ip":                 null,
  "host_mac":                null,
  "host_domain":             null,
  "host_os":                 null,

  "user_id":                 "IKP0472",
  "user_name":               "IKP0472",
  "user_type":               "REGULAR",

  "mount_point":             null,
  "volume_label":            null,
  "file_system_type":        null,

  "risk_score":              null,
  "risk_factors":            [],
  "is_storage_device":       null,
  "is_authorized_device":    null,
  "is_new_device_for_user":  null,
  "is_new_device_for_host":  null,
  "session_duration_seconds": null,
  "device_connection_count_1h": null,
  "concurrent_device_count": null,
  "logon_event_uid":         null,

  "source_file":             "device.csv",
  "source_line_number":      2,
  "additional_fields":       null
}
```

---

### 4.4 Attribute Mapping Tables

#### Mapping: `event_action` (from source `activity`)

| Canonical Value | Source Variants | Description | ECS `event.action` | Windows Event |
|---|---|---|---|---|
| `CONNECT` | `Connect`, `connect`, `Connected`, `Device connected`, `device_connect`, `Plugin`, `plugged_in`, `Attach`, `attached`, `devnodes_changed`, `device_arrival`, `DeviceArrival`, `insertdevice`, `USB inserted`, `storage_connect` | Peripheral device plugged in or recognized | `connected` | `DeviceSetupManager`, Event 6416 |
| `DISCONNECT` | `Disconnect`, `disconnect`, `Disconnected`, `Device disconnected`, `device_disconnect`, `Unplug`, `unplugged`, `Detach`, `detached`, `device_removal`, `DeviceRemoval`, `USB removed`, `storage_disconnect`, `eject` | Peripheral device removed or ejected | `disconnected` | Event 6416 (remove) |
| `INSTALL` | `Install`, `installed`, `device_install`, `driver_install`, `new_device`, `NewDevice`, `DeviceInstalled`, `first_connection` | New device driver installed | `installed` | Event 20001 |
| `UNINSTALL` | `Uninstall`, `uninstalled`, `device_uninstall`, `driver_uninstall`, `DeviceUninstalled` | Device driver removed | `uninstalled` | — |
| `MOUNT` | `Mount`, `mounted`, `volume_mount`, `VolumeMounted`, `drive_letter_assigned`, `MountVolume` | Volume mounted and accessible | `mounted` | Event 98 (StorPort) |
| `UNMOUNT` | `Unmount`, `unmounted`, `volume_unmount`, `VolumeUnmounted`, `eject_volume`, `drive_letter_removed` | Volume unmounted | `unmounted` | — |
| `BLOCKED` | `Blocked`, `blocked`, `device_blocked`, `access_denied`, `policy_blocked`, `BLOCKED_BY_POLICY`, `DLP_block` | Device connection blocked by policy | `blocked` | DLP/MDM tools |
| `UNKNOWN` | Any unmatched value | Fallback | `unknown` | — |

---

#### Mapping: `event_outcome` (from `event_action`)

| `event_action` | `event_outcome` |
|---|---|
| `CONNECT` | `SUCCESS` |
| `DISCONNECT` | `SUCCESS` |
| `INSTALL` | `SUCCESS` |
| `UNINSTALL` | `SUCCESS` |
| `MOUNT` | `SUCCESS` |
| `UNMOUNT` | `SUCCESS` |
| `BLOCKED` | `FAILURE` |
| `UNKNOWN` | `UNKNOWN` |

---

#### Mapping: `device_type` (inferred from context)

Since the source has no device type information, this is set to `UNKNOWN` initially but can be enriched from Windows Security Event 6416 or MDM logs. The canonical values and their real-world sources:

| Canonical Value | Windows Class | USB Class Code | Common Example |
|---|---|---|---|
| `USB_STORAGE` | `DiskDrive`, `USBSTOR` | `08h` | Flash drives, external HDDs |
| `USB_HID` | `HIDClass` | `03h` | Keyboards, mice |
| `USB_PRINTER` | `Printer` | `07h` | USB printers |
| `USB_AUDIO` | `MEDIA` | `01h` | Headsets, audio adapters |
| `BLUETOOTH` | `Bluetooth` | — | BT adapters, BT devices |
| `THUNDERBOLT` | — | — | Thunderbolt docks |
| `NETWORK_ADAPTER` | `Net` | `02h` / `E0h` | USB network cards |
| `CD_DVD` | `CDROM` | `08h` | Optical drives |
| `SMARTCARD_READER` | `SmartCardReader` | `0Bh` | PIV, CAC readers |
| `BIOMETRIC` | `Biometric` | `0Fh` | Fingerprint readers |
| `UNKNOWN` | Any | Any | Default |

---

#### Mapping: `event_severity` for Device Events (derived rule)

| Condition | Severity |
|---|---|
| Normal hours connect, authorized device | `INFORMATIONAL` |
| Storage device connected (any time) | `LOW` |
| Device connected after hours | `LOW` |
| Storage device connected after hours | `MEDIUM` |
| Device blocked by policy | `MEDIUM` |
| Unauthorized device (not in whitelist) | `HIGH` |
| Large capacity storage device (>64 GB) | `HIGH` |
| Unauthorized storage after hours | `HIGH` |
| Multiple rapid connect/disconnect cycles (>5 in 1h) | `MEDIUM` |
| CRITICAL: Exfiltration indicator pattern match | `CRITICAL` |

---

## 5. Enumeration Master Lists

### 5.1 `event_action` — Logon Schema

```json
{
  "LOGON_EVENT_ACTION_ENUM": [
    "LOGON",
    "LOGOFF",
    "FAILED_LOGON",
    "ELEVATE",
    "SESSION_LOCK",
    "SESSION_UNLOCK",
    "RECONNECT",
    "DISCONNECT",
    "UNKNOWN"
  ]
}
```

### 5.2 `event_action` — Device Schema

```json
{
  "DEVICE_EVENT_ACTION_ENUM": [
    "CONNECT",
    "DISCONNECT",
    "INSTALL",
    "UNINSTALL",
    "MOUNT",
    "UNMOUNT",
    "BLOCKED",
    "UNKNOWN"
  ]
}
```

### 5.3 `event_outcome` (both schemas)

```json
{
  "EVENT_OUTCOME_ENUM": ["SUCCESS", "FAILURE", "UNKNOWN"]
}
```

### 5.4 `event_severity` (both schemas)

```json
{
  "EVENT_SEVERITY_ENUM": [
    "INFORMATIONAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
  ]
}
```

### 5.5 `logon_protocol` (logon schema)

```json
{
  "LOGON_PROTOCOL_ENUM": [
    "NTLM", "KERBEROS", "LDAP", "OAUTH2", "SAML",
    "RADIUS", "NEGOTIATE", "LOCAL", "UNKNOWN"
  ]
}
```

### 5.6 `logon_method` (logon schema)

```json
{
  "LOGON_METHOD_ENUM": [
    "PASSWORD", "MFA", "CERTIFICATE", "SSO",
    "BIOMETRIC", "TOKEN", "SMARTCARD", "PASSWORDLESS", "OTHER"
  ]
}
```

### 5.7 `user_type` (both schemas)

```json
{
  "USER_TYPE_ENUM": [
    "REGULAR", "MACHINE", "SERVICE_ACCOUNT",
    "ADMIN", "GUEST", "SYSTEM", "UNKNOWN"
  ]
}
```

### 5.8 `device_type` (device schema)

```json
{
  "DEVICE_TYPE_ENUM": [
    "USB_STORAGE", "USB_HID", "USB_PRINTER", "USB_AUDIO",
    "BLUETOOTH", "THUNDERBOLT", "NETWORK_ADAPTER", "CD_DVD",
    "SMARTCARD_READER", "BIOMETRIC", "UNKNOWN"
  ]
}
```

---

## References 

| Source | URL |
|---|---|
| Microsoft ASIM Authentication Schema | https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication |
| Microsoft ASIM Schema Overview | https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-schemas |
| Elastic Common Schema (ECS) | https://www.elastic.co/docs/reference/ecs |
| OSSEM — logon entity | https://ossemproject.com/cdm/entities/logon.html |
| OSSEM — device entity | https://ossemproject.com/cdm/entities/device.html |
| Google Chronicle UDM Overview | https://docs.cloud.google.com/chronicle/docs/reference/important-udm-fields |
| Google Chronicle UDM Usage Guide | https://docs.cloud.google.com/chronicle/docs/unified-data-model/udm-usage |
| AWS Security Finding Format (ASFF) | https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html |
| NXLog LEEF Integration | https://docs.nxlog.co/integrate/leef.html |
| Sigma Detection Format | https://sigmahq.io/docs/basics/rules.html |
| Windows Security Event 4624 | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 |
| Windows Device Connect Event 6416 | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6416 |