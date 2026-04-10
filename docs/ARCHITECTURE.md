# SentinelX Architecture Notes

## Detection Flow

1. Scanner enumerates files from selected target.
2. Each file is hashed using SHA-256.
3. Hash is checked against local SQLite `signatures`.
4. Positive match produces detection event and quarantine action.
5. Session summary and detections are persisted for analytics and reports.

## Realtime Flow

1. `watchdog` observer tracks created/modified events on selected folders.
2. Event handler classifies event and hashes file when possible.
3. Signature match updates event stream as `threat detected`.
4. Dashboard and realtime panels refresh from event and detection data.

## Data Layer

- `signatures`: local IOC-like signature table
- `scans`: session telemetry and summary
- `detections`: per-file detection events
- `quarantine`: isolated artifacts and metadata
- `realtime_events`: monitor and scan event timeline
