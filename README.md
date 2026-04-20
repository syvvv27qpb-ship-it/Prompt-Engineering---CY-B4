# CIDR Dataset — Source Files Overview

This document provides an abstract description of the three raw data files used as the foundation for the Cybersecurity Risk Classification project. These files represent behavioral log data collected across a monitored environment and will serve as the basis for schema standardization and risk classification in subsequent project phases.

---

## Dataset Summary

| File | Records | Attributes | Users | Date Range |
|---|---|---|---|---|
| `file_access.csv` | 200 | 6 | 3 | Jan 4 – Jan 19, 2010 |
| `login.csv` | 200 | 5 | 3 | Jan 2 – Jan 25, 2010 |
| `device.csv` | 200 | 5 | 3 | Jan 4 – Jan 25, 2010 |

All three files share the same user population of 3: **IKP0472**, **NGF0157**, and **NOB0181**.

---

## File Descriptions

### `file_access.csv`
Logs file interaction events performed by users on their assigned workstations. Each record captures a single file access event, including a description of the accessed content.

**Attributes:**
- `id` — Unique event identifier (format: `{FA-XXXX-XXXX}`)
- `date` — Timestamp of the file access event
- `user` — User ID of the individual who accessed the file
- `pc` — Workstation identifier associated with the event
- `filename` — Name of the accessed file
- `content` — Brief textual description of the file's content

---

### `login.csv`
Logs authentication activity, recording when users log on to or log off from workstations. Each record represents a single authentication event.

**Attributes:**
- `id` — Unique event identifier (format: `{XXXXX-XXXXXXXX-XXXXXXXX}`)
- `date` — Timestamp of the authentication event
- `user` — User ID performing the action
- `pc` — Workstation identifier
- `activity` — Type of event: `Logon` or `Logoff`

---

### `device.csv`
Logs peripheral or external device connection events on workstations. Each record captures a connect or disconnect action.

**Attributes:**
- `id` — Unique event identifier (format: `{DV-XXXX-XXXXXXXXXXXX}`)
- `date` — Timestamp of the device event
- `user` — User ID associated with the event
- `pc` — Workstation identifier
- `activity` — Type of event: `Connect` or `Disconnect`

---

## Primary flags to know about

- All three files cover a contiguous observation window spanning roughly **January 2 – January 25, 2010**.
- PC-8267 is absent from device.csv (No device was never attached to)
- One file access event occurs after logoff (NGF0157, PC-8267, Jan 14): NGF0157 logged off PC-8267 at 11:04, but a file access to old_scan_copy.pdf is recorded at 12:14:40 on the same machine — over an hour after the session ended. The login record shows no second logon for that machine that day. This is the single most notable logical inconsistency in the dataset.
- IKP0472 has one unclosed session (Jan 25, PC-3842): The dataset ends with IKP0472 logging into PC-3842 on Jan 25 at 08:02 and never logging off.