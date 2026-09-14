# Integration contract

Backend API prefix /api; Bearer token required for every /api request except /api/health.
Errors: {detail: string}. Frontend token in sessionStorage, entered in connection screen.
GET /api/health -> {status, version}; GET /api/status -> {components, approved, pending, blocked, scans, audit_valid, monitor_running, policy_version, enforcement_mode:"integration-gate", data_dir}.
GET /api/components -> component[]; POST /api/components/discover {path} -> component[]; GET /api/components/{id} -> component; POST /api/components/{id}/refresh -> component.
Component: {id,name,kind,source_path,state,snapshot_valid:boolean,source_valid:boolean,version,raw_hash,canonical_hash,semantic_fingerprint,approved_at,approved_by,approval_id,previous_version,action,severity,changes:[],findings:[],content,updated_at}. Displayed content is redacted. Inventory reads verify persisted snapshot identity/content/version against signed history in one batch; they do not reread sources or authorize use. Unverifiable snapshots project BLOCKED/BLOCK, snapshot_valid=false, source_valid=false, content=null and null current approval fields, with a fixed SNAPSHOT_INTEGRITY_FAILED finding and typed diagnostic metadata; stored evidence is unchanged. snapshot_valid=true does not replace the current-source, signature, lifecycle and policy checks of the gate. State: PENDING_APPROVAL, APPROVED, REAPPROVAL_REQUIRED, BLOCKED, QUARANTINED, REVOKED. Changes: {path,old,new,severity,category}. Findings: {rule_id,title,severity,category,evidence,location,layer}.
POST /api/components/{id}/approve {canonical_hash,version,approver,note} -> component (409 on stale hash/version or changed source); POST /api/components/{id}/revoke {reason} -> component.
POST /api/components/{id}/quarantine {reason} -> component (logical quarantine, originals untouched).
GET /api/components/{id}/history -> version[]; GET /api/components/{id}/approval -> signed approval object.
POST /api/scan multipart file -> scan report; POST /api/scan/path {path} -> scan report; GET /api/scans -> scan report[]; GET /api/scans/{id} -> report.
Scan report: {id,filename,sha256,status,risk_score,severity,findings:[],extraction:{format,characters,segments,truncated},rules_version,created_at,duration_ms,limitations:[]}. Status ALLOWED, FLAGGED, QUARANTINED, BLOCKED. Findings as above plus optional line,encoding. Scanner does not promise safe semantic sanitization.
GET /api/audit -> event[] {sequence,timestamp,event_type,component_id,details,previous_hash,hash}; GET /api/audit/verify -> {valid,checked,error?,head_hash}; GET /api/audit/export -> JSON downloadable.
GET /api/policy -> {version,format_only_action,semantic_change_action,security_change_action,unapproved_action,scan_block_score,scan_quarantine_score,scan_flag_score}; PUT /api/policy same body -> policy. action enum ALLOW,WARN,REQUIRE_REAPPROVAL,QUARANTINE,BLOCK. Editing policy increments version automatically.
GET /api/monitor -> {running,paths,errors}; POST /api/monitor {enabled:boolean} -> same.
POST /api/gate {component_id,canonical_hash?,version?} -> {allowed,action,reason,component_id,canonical_hash,version}; API is a pre-use decision gate, not a transparent MCP proxy. Fresh source reread on every gate call.

Python core public interface (agent implementing may refine and message root): GuardStore(data_dir: Path), discover(path: Path)->list[dict], list_components()->list[dict], get_component(id)->dict, refresh(id)->dict, approve(id,canonical_hash,version,approver,note="")->dict, revoke(id,reason)->dict, quarantine(id,reason)->dict, history(id)->list[dict], approval(id)->dict, gate(id,canonical_hash=None,version=None)->dict, get_policy()->dict, set_policy(dict)->dict, audit_events(limit=200)->list[dict], verify_audit()->dict, append_audit(event_type,component_id,details)->dict. Threadsafe store. Raise ValueError for invalid, KeyError for missing, ConflictError for stale/tampered.
Scanner public interface: Scanner(rules_path: Path|None=None, max_input_size=10485760, timeout=8.0), scan_bytes(data: bytes, filename: str)->dict. Direct callable; production API wraps extraction in bounded subprocess. Reports are plain JSON. Agent owns scanner.py, extraction.py, rules.json, test_scanner.py. Core owns core.py, canonical.py, tests/test_core.py. Root owns API, scanner worker, monitor, CLI, scripts, integration tests and docs. Frontend agent owns frontend only.

## Linux expansion

Primary platform Linux; project /mnt/d/Cheker. app/runtime-linux + app/data-linux, dev/.venv + dev/.dev-data-linux.
Reports add verdict VALID|INFECTED|CORRUPTED|REVIEW_REQUIRED|UNSCANNABLE, analysis_complete, optional failure_kind MALFORMED|UNSUPPORTED|RESOURCE_LIMIT|INTERNAL_ERROR|UNSAFE_CONTENT, source_path,size_bytes.
GET /api/scan/stats?verdict=ALL&query= -> {analyzed,infected,corrupted,valid,review_required,unscannable,blocked,unique_files,last_scan_at,matched}. Global counts remain global; matched applies filters; unique_files=distinct nonemptySHA256.
GET /api/scans?limit=100&offset=0&verdict=ALL&query= -> report[]; pagination1..500.
GET /api/filewatch ->{running,roots:[{id,path,recursive,enabled,files_seen,last_scan_at,error,last_job}]}; POST /api/filewatch {enabled} ->same.
POST /api/filewatch/roots {path,recursive:false}->root; DELETE /api/filewatch/roots/{id}->{removed:id}; PUT same {enabled}->root.
POST /api/filewatch/roots/{id}/scan ->job {id,root_id,status,started_at,completed_at,files_seen,scanned,unchanged,skipped,failed,removed,limited,report_ids,errors:[{path,code,message}],duration_ms}. Long running <=60sec boundedpass. COMPLETED describes traversal; individual reports may be blocked. PARTIAL must remain visible.
Reports.scan(data,filename,source_path=None); Reports.record_failure(filename,source_path,reason,code,sha256=None); Reports.stats(verdict='ALL',query=''); Reports.list(limit=100,offset=0,verdict='ALL',query='').

## Explicit HTML text copies

POST /api/sanitizations/html accepts multipart `file` and optional form `expected_sha256`.
POST /api/sanitizations/html/path accepts `{path,expected_sha256?}`. The Linux path route rejects symlink traversal, hard links, nonregular files and application data. Expected SHA-256 mismatch is409 before scanning.
GET /api/sanitizations?limit=50&offset=0 returns metadata[] (limit1..100); GET /api/sanitizations/{id} returns metadata.
Metadata: `{id,created_at,profile:"html-text-v1",transformation_status:"SANITIZED"|"FAILED",delivery_status:"ALLOWED"|"DENIED",reason,input_filename,output_filename,input_sha256:string|null,output_sha256:string|null,input_size_bytes:number|null,output_size_bytes:number|null,input_report_id,output_report_id:string|null,omitted_counts:Record<string,number>}`.
Only POST adds `delivery:null|{encoding:"base64",media_type:"text/plain;charset=utf-8",data_base64}`. GET never returns the copy. Failure to record operation/audit produces503 without delivery; initial worker contention produces429. Partial completed stages may instead produce a recorded DENIED operation.
The original is scanned before conversion; exact output bytes are independently scanned and require complete VALID/ALLOWED, empty findings, matching hash/size and current policy. Transformation success alone never authorizes delivery. The two ordinary analyses contribute to existing scan totals; no sixth verdict is added. Inputs max10MiB, text output max256KiB, transform worker transport max1MiB, shared two-worker pool.
Implementation and supported profile: docs/SANITIZZAZIONE.md. Future packaged extractor registration: docs/ESTRATTORI.md.
