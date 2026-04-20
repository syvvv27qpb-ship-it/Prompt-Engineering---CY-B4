# CIDR Dataset — Source Files Overview

This document provides an abstract description of the three raw data files used as the foundation for the Cybersecurity Risk Classification project. These files represent behavioral log data collected across a monitored environment and will serve as the basis for schema standardization and risk classification in subsequent project phases.

---

## Dataset Summary

| File | Records | Attributes | Users | Date Range |
|---|---|---|---|---|
| `file_access.csv` | 200 | 6 | 3 | Jan 4 – Jan 19, 2010 |
| `login.csv` | 199 | 5 | 3 | Jan 2 – Jan 25, 2010 |
| `device.csv` | 200 | 5 | 3 | Jan 4 – Jan 25, 2010 |

All three files share the same user population: **IKP0472**, **NGF0157**, and **NOB0181**.

---

## File Descriptions

### `file_access.csv`
Logs file interaction events performed by users on their assigned workstations. Each record captures a single file access event, including a description of the accessed content. This dataset is the most semantically rich of the three, as it includes a plain-text content field describing the nature of the file involved.

**Attributes:**
- `id` — Unique event identifier (format: `{FA-XXXX-XXXX}`)
- `date` — Timestamp of the file access event
- `user` — User ID of the individual who accessed the file
- `pc` — Workstation identifier associated with the event
- `filename` — Name of the accessed file
- `content` — Brief textual description of the file's content

---

### `login.csv`
Logs authentication activity, recording when users log on to or log off from workstations. Each record represents a single authentication event, making this file useful for reconstructing session timelines and cross-machine activity patterns.

**Attributes:**
- `id` — Unique event identifier (format: `{XXXXX-XXXXXXXX-XXXXXXXX}`)
- `date` — Timestamp of the authentication event
- `user` — User ID performing the action
- `pc` — Workstation identifier
- `activity` — Type of event: `Logon` or `Logoff`

---

### `device.csv`
Logs peripheral or external device connection events on workstations. Each record captures a connect or disconnect action, providing insight into removable media or external device usage patterns throughout the observation period.

**Attributes:**
- `id` — Unique event identifier (format: `{DV-XXXX-XXXXXXXXXXXX}`)
- `date` — Timestamp of the device event
- `user` — User ID associated with the event
- `pc` — Workstation identifier
- `activity` — Type of event: `Connect` or `Disconnect`

---

## Notes

- All three files cover a contiguous observation window spanning roughly **January 2 – January 25, 2010**.
- The shared user set and overlapping date ranges make these files naturally joinable for multi-source behavioral analysis.
- Schema standardization and risk classification will be addressed in subsequent project phases.
