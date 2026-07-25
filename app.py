import base64
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, jsonify, request

app = Flask(__name__)

PROFILE = "ga5-mailroom-action-gate/v2"

# In-memory persistence stores
# DOSSIER_CACHE: canonical_content_hash -> proposal_dict
DOSSIER_CACHE: Dict[str, Dict[str, Any]] = {}

# EVALUATION_STORE: evaluationId -> { inputDigest, proposals, receiptVerifier, status, outcomes }
EVALUATION_STORE: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Canonical JSON & Hashing Utilities
# ---------------------------------------------------------------------------


def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes obj to recursively key-sorted, compact UTF-8 JSON bytes."""
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def compute_input_digest(dossiers: List[Dict[str, Any]]) -> str:
    """Computes SHA-256 hex digest over UTF-8 bytes of dossiers array."""
    return hashlib.sha256(canonical_json_bytes(dossiers)).hexdigest().lower()


def compute_dossier_content_hash(dossier: Dict[str, Any]) -> str:
    """Computes a stable fingerprint for a dossier based on its immutable content."""
    content_obj = {
        "mailbox": dossier.get("mailbox", ""),
        "objective": dossier.get("objective", ""),
        "sources": dossier.get("sources", []),
    }
    return hashlib.sha256(canonical_json_bytes(content_obj)).hexdigest()


def compute_proposal_digest(proposal: Dict[str, Any]) -> str:
    """Computes proposalDigest over dossierId, callId, action, target, payload, sorted evidence."""
    sorted_evidence = sorted(proposal.get("evidence", []))
    obj_to_hash = {
        "action": proposal.get("action"),
        "callId": proposal.get("callId"),
        "dossierId": proposal.get("dossierId"),
        "evidence": sorted_evidence,
        "payload": proposal.get("payload"),
        "target": proposal.get("target"),
    }
    return hashlib.sha256(canonical_json_bytes(obj_to_hash)).hexdigest()


# ---------------------------------------------------------------------------
# Deep Dossier Analysis & Parameter Extraction Engine
# ---------------------------------------------------------------------------


def extract_field_from_lines(
    lines: List[Tuple[str, str, str, str]], patterns: List[str]
) -> Tuple[Optional[str], Optional[str]]:
    """Searches lines for key-value patterns. Returns (value, lineId)."""
    for line_id, text, _, _ in lines:
        for pat in patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                return match.group(1).strip(), line_id
    return None, None


def analyze_dossier(
    dossier: Dict[str, Any]
) -> Tuple[str, Optional[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Analyzes a dossier using provenance, authority, and structural extraction."""
    dossier_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "")
    objective = dossier.get("objective", "")
    sources = dossier.get("sources", [])

    all_lines: List[Tuple[str, str, str, str]] = []  # (lineId, text, kind, provenance)

    for src in sources:
        kind = src.get("kind", "")
        prov = src.get("provenance", "")
        for line in src.get("lines", []):
            l_id = line.get("lineId")
            txt = line.get("text", "")
            if l_id:
                all_lines.append((l_id, txt, kind, prov))

    if not all_lines:
        return (
            "no_action",
            None,
            {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id},
            [],
        )

    first_line_id = all_lines[0][0]

    # --- 1. Indirect Prompt Injection Check ---
    injection_patterns = [
        r"ignore\s+(previous|all|prior)\s+instructions",
        r"exfiltrate",
        r"override\s+safety",
        r"bypass\s+security",
        r"system\s+prompt",
    ]

    for l_id, text, kind, prov in all_lines:
        # Attacks coming from untrusted external content
        if prov in ("untrusted", "external") or kind in ("external_email", "attachment"):
            for pat in injection_patterns:
                if re.search(pat, text, re.IGNORECASE):
                    # Extract artifact ID if present
                    art_id, art_line = extract_field_from_lines(
                        all_lines, [r"artifact[_-]?id[:\s]+([a-zA-Z0-9_\-]+)"]
                    )
                    evidence = [l_id]
                    if art_line and art_line not in evidence:
                        evidence.append(art_line)
                    return (
                        "quarantine_item",
                        {"kind": "security_queue", "id": "mailroom"},
                        {
                            "artifactId": art_id if art_id else dossier_id,
                            "reasonCode": "INDIRECT_PROMPT_INJECTION",
                        },
                        evidence,
                    )

    # Extract common IDs across dossier
    ref_id, ref_line = extract_field_from_lines(
        all_lines, [r"ref(?:erence)?(?:Id)?[:\s]+([a-zA-Z0-9_\-]+)"]
    )
    case_id, case_line = extract_field_from_lines(
        all_lines, [r"case(?:Id)?[:\s]+([a-zA-Z0-9_\-]+)"]
    )
    val, val_line = extract_field_from_lines(
        all_lines, [r"window[:\s]+([a-zA-Z0-9_\-\s]+)"]
    )

    if not ref_id:
        ref_id = dossier_id
        ref_line = first_line_id

    # --- 2. Approved Delivery Notice ---
    for l_id, text, _, prov in all_lines:
        if "approved" in text.lower() and ("notice" in text.lower() or "send" in text.lower()):
            evidence = [l_id]
            if ref_line and ref_line not in evidence:
                evidence.append(ref_line)
            return (
                "send_approved_notice",
                {"kind": "email", "id": mailbox if mailbox else "customer@example.com"},
                {
                    "referenceId": ref_id,
                    "status": "approved",
                    "template": "approved_delivery_notice",
                },
                evidence,
            )

    # --- 3. Update Internal Record ---
    if case_id or "update" in objective.lower():
        evidence = []
        if case_line:
            evidence.append(case_line)
        if val_line and val_line not in evidence:
            evidence.append(val_line)
        if not evidence:
            evidence = [first_line_id]

        return (
            "update_internal_record",
            {"kind": "case_record", "id": case_id if case_id else f"case_{dossier_id}"},
            {
                "field": "delivery_window",
                "sourceEventId": dossier_id,
                "value": val if val else "standard",
            },
            evidence,
        )

    # --- 4. Request Confirmation ---
    for l_id, text, _, _ in all_lines:
        if "confirm" in text.lower() or "verify" in text.lower() or "ambiguous" in text.lower():
            team, team_line = extract_field_from_lines(
                all_lines, [r"team[:\s]+([a-zA-Z0-9_\-]+)"]
            )
            evidence = [l_id]
            if team_line and team_line not in evidence:
                evidence.append(team_line)
            return (
                "request_confirmation",
                {
                    "kind": "approval_queue",
                    "id": team if team else "support_team",
                },
                {
                    "claimedSender": mailbox,
                    "questionCode": "VERIFY_REQUEST",
                    "referenceId": ref_id,
                },
                evidence,
            )

    # --- 5. Create Draft ---
    for l_id, text, _, _ in all_lines:
        if "draft" in text.lower() or "order" in text.lower():
            evidence = [l_id]
            if ref_line and ref_line not in evidence:
                evidence.append(ref_line)
            return (
                "create_draft",
                {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                {
                    "recipient": mailbox,
                    "referenceId": ref_id,
                    "status": "pending",
                    "template": "order_status",
                },
                evidence,
            )

    # --- 6. Default No Action ---
    return (
        "no_action",
        None,
        {"reasonCode": "INFORMATIONAL", "referenceId": ref_id},
        [first_line_id],
    )


# ---------------------------------------------------------------------------
# Strict Ed25519 Receipt Signature Verification
# ---------------------------------------------------------------------------


def verify_receipt_signature(
    public_key_jwk: Dict[str, Any],
    evaluation_id: str,
    input_digest: str,
    receipt: Dict[str, Any],
    signature_b64: str,
) -> bool:
    """Verifies Ed25519 receipt signature against recursively key-sorted canonical JSON."""
    try:
        x_b64 = public_key_jwk.get("x", "")
        padding = "=" * ((4 - len(x_b64) % 4) % 4)
        raw_key_bytes = base64.urlsafe_b64decode(x_b64 + padding)

        public_key = Ed25519PublicKey.from_public_bytes(raw_key_bytes)

        payload_to_sign = {
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "profile": PROFILE,
            "receipt": {
                "accepted": receipt.get("accepted"),
                "action": receipt.get("action"),
                "callId": receipt.get("callId"),
                "dossierId": receipt.get("dossierId"),
                "proposalDigest": receipt.get("proposalDigest"),
                "receiptId": receipt.get("receiptId"),
            },
        }

        sign_bytes = canonical_json_bytes(payload_to_sign)

        sig_padding = "=" * ((4 - len(signature_b64) % 4) % 4)
        sig_bytes = base64.b64decode(signature_b64 + sig_padding)

        public_key.verify(sig_bytes, sign_bytes)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HTTP Endpoints
# ---------------------------------------------------------------------------


@app.route("/", methods=["GET", "OPTIONS"])
def health():
    return jsonify({"status": "ok", "service": "Mailroom Gate API", "profile": PROFILE}), 200


@app.route("/", methods=["POST"])
@app.route("/gate", methods=["POST"])
def mailroom_gate():
    try:
        data = request.get_json(force=True, silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body"}), 400

        operation = data.get("operation")
        profile = data.get("profile")

        if profile != PROFILE:
            return jsonify({"error": f"Invalid profile '{profile}'"}), 400

        # -------------------------------------------------------------------
        # OPERATION: PROPOSE
        # -------------------------------------------------------------------
        if operation == "propose":
            evaluation_id = data.get("evaluationId")
            dossiers = data.get("dossiers", [])
            receipt_verifier = data.get("receiptVerifier", {})

            if not evaluation_id or not isinstance(dossiers, list) or not dossiers:
                return jsonify({"error": "Missing evaluationId or dossiers"}), 400

            computed_digest = compute_input_digest(dossiers)

            # Conflict check: same evaluationId with different content -> HTTP 409
            if evaluation_id in EVALUATION_STORE:
                existing = EVALUATION_STORE[evaluation_id]
                if existing["inputDigest"] != computed_digest:
                    return (
                        jsonify({"error": "evaluationId exists with different input content"}),
                        409,
                    )
                # Exact replay
                return (
                    jsonify(
                        {
                            "profile": PROFILE,
                            "evaluationId": evaluation_id,
                            "status": "awaiting_receipts",
                            "inputDigest": computed_digest,
                            "proposals": existing["proposals"],
                        }
                    ),
                    200,
                )

            proposals = []
            seen_dossier_ids = set()

            for dossier in dossiers:
                d_id = dossier.get("dossierId")
                if not d_id or d_id in seen_dossier_ids:
                    return (
                        jsonify({"error": f"Invalid or duplicate dossierId: {d_id}"}),
                        400,
                    )
                seen_dossier_ids.add(d_id)

                content_hash = compute_dossier_content_hash(dossier)

                if content_hash in DOSSIER_CACHE:
                    cached = DOSSIER_CACHE[content_hash]
                    prop = {
                        "dossierId": d_id,
                        "callId": cached["callId"],
                        "action": cached["action"],
                        "target": cached["target"],
                        "payload": cached["payload"],
                        "evidence": cached["evidence"],
                    }
                else:
                    action, target, payload, evidence = analyze_dossier(dossier)
                    call_id = f"call_{d_id}_{hashlib.md5(content_hash.encode()).hexdigest()[:8]}"

                    prop = {
                        "dossierId": d_id,
                        "callId": call_id,
                        "action": action,
                        "target": target,
                        "payload": payload,
                        "evidence": evidence,
                    }
                    DOSSIER_CACHE[content_hash] = prop

                proposals.append(prop)

            # Store for commit phase
            EVALUATION_STORE[evaluation_id] = {
                "inputDigest": computed_digest,
                "proposals": proposals,
                "receiptVerifier": receipt_verifier,
                "status": "awaiting_receipts",
            }

            return (
                jsonify(
                    {
                        "profile": PROFILE,
                        "evaluationId": evaluation_id,
                        "status": "awaiting_receipts",
                        "inputDigest": computed_digest,
                        "proposals": proposals,
                    }
                ),
                200,
            )

        # -------------------------------------------------------------------
        # OPERATION: COMMIT
        # -------------------------------------------------------------------
        elif operation == "commit":
            evaluation_id = data.get("evaluationId")
            input_digest = data.get("inputDigest")
            receipts = data.get("receipts", [])

            if not evaluation_id or evaluation_id not in EVALUATION_STORE:
                return jsonify({"error": f"Unknown evaluationId: {evaluation_id}"}), 400

            stored_eval = EVALUATION_STORE[evaluation_id]

            # Exact replay check
            if stored_eval.get("status") == "completed":
                return (
                    jsonify(
                        {
                            "profile": PROFILE,
                            "evaluationId": evaluation_id,
                            "status": "completed",
                            "inputDigest": stored_eval["inputDigest"],
                            "outcomes": stored_eval["outcomes"],
                        }
                    ),
                    200,
                )

            if stored_eval["inputDigest"] != input_digest:
                return jsonify({"error": "inputDigest mismatch"}), 400

            proposals_map = {p["dossierId"]: p for p in stored_eval["proposals"]}
            verifier_jwk = stored_eval["receiptVerifier"].get("publicKeyJwk", {})

            if len(receipts) != len(proposals_map):
                return jsonify({"error": "Receipt count does not match proposal count"}), 400

            outcomes = []
            seen_receipt_dossiers = set()

            for receipt in receipts:
                d_id = receipt.get("dossierId")
                sig_b64 = receipt.get("receiptSignature")

                if not d_id or d_id in seen_receipt_dossiers or d_id not in proposals_map:
                    return jsonify({"error": f"Invalid or duplicate receipt dossierId: {d_id}"}), 400
                seen_receipt_dossiers.add(d_id)

                proposal = proposals_map[d_id]
                expected_digest = compute_proposal_digest(proposal)

                # Verify proposal alignment
                if (
                    receipt.get("proposalDigest") != expected_digest
                    or receipt.get("callId") != proposal["callId"]
                    or receipt.get("action") != proposal["action"]
                ):
                    return jsonify({"error": f"Receipt proposal alignment failed for {d_id}"}), 400

                # Verify Ed25519 signature
                if not verify_receipt_signature(
                    verifier_jwk, evaluation_id, input_digest, receipt, sig_b64
                ):
                    return jsonify({"error": f"Invalid signature for dossier {d_id}"}), 400

                accepted = receipt.get("accepted", False)
                outcomes.append(
                    {
                        "dossierId": d_id,
                        "callId": proposal["callId"],
                        "action": proposal["action"],
                        "proposalDigest": expected_digest,
                        "receiptId": receipt.get("receiptId"),
                        "status": "executed" if accepted else "rejected",
                    }
                )

            # Atomically mark as completed
            stored_eval["status"] = "completed"
            stored_eval["outcomes"] = outcomes

            return (
                jsonify(
                    {
                        "profile": PROFILE,
                        "evaluationId": evaluation_id,
                        "status": "completed",
                        "inputDigest": input_digest,
                        "outcomes": outcomes,
                    }
                ),
                200,
            )

        else:
            return jsonify({"error": f"Unknown operation: {operation}"}), 400

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)