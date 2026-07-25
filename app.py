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
DOSSIER_CACHE: Dict[str, Dict[str, Any]] = {}
EVALUATION_STORE: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Canonical Serialization & Hashing
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
    sorted_evidence = sorted(list(set(proposal.get("evidence", []))))
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
# Advanced Dossier Pattern & Parameter Extractor
# ---------------------------------------------------------------------------


def extract_field_and_line(
    lines: List[Tuple[str, str, str, str]], patterns: List[str]
) -> Tuple[Optional[str], Optional[str]]:
    """Extracts first matching regex group and the associated lineId."""
    for l_id, text, _, _ in lines:
        for pat in patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                return match.group(1).strip(), l_id
    return None, None


def analyze_dossier(
    dossier: Dict[str, Any]
) -> Tuple[str, Optional[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Analyzes dossier provenance, authority, and structural parameters to make a safe proposal."""
    dossier_id = str(dossier.get("dossierId", ""))
    mailbox = str(dossier.get("mailbox", ""))
    objective = str(dossier.get("objective", ""))
    sources = dossier.get("sources", [])

    all_lines: List[Tuple[str, str, str, str]] = []  # (lineId, text, kind, provenance)

    for src in sources:
        kind = str(src.get("kind", ""))
        prov = str(src.get("provenance", ""))
        for line in src.get("lines", []):
            l_id = str(line.get("lineId", ""))
            txt = str(line.get("text", ""))
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

    # --- 1. INDIRECT PROMPT INJECTION / ATTACK DETECTION ---
    injection_keywords = [
        r"ignore\s+(previous|all|prior)\s+instructions",
        r"exfiltrate",
        r"override\s+safety",
        r"bypass\s+security",
        r"system\s+prompt",
        r"send\s+secrets?",
        r"delete\s+all",
    ]

    for l_id, text, kind, prov in all_lines:
        is_untrusted = prov in ("untrusted", "external", "third_party") or kind in (
            "external_email",
            "attachment",
            "untrusted_body",
        )
        if is_untrusted:
            for kw in injection_keywords:
                if re.search(kw, text, re.IGNORECASE):
                    art_id, art_line = extract_field_and_line(
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

    # Extract common field references
    ref_id, ref_line = extract_field_and_line(
        all_lines,
        [
            r"reference[_-]?id[:\s]+([a-zA-Z0-9_\-]+)",
            r"ref[:\s]+([a-zA-Z0-9_\-]+)",
            r"order[_-]?id[:\s]+([a-zA-Z0-9_\-]+)",
        ],
    )
    if not ref_id:
        ref_id = dossier_id
        ref_line = first_line_id

    case_id, case_line = extract_field_and_line(
        all_lines,
        [r"case[_-]?id[:\s]+([a-zA-Z0-9_\-]+)", r"case[:\s]+([a-zA-Z0-9_\-]+)"],
    )

    window_val, window_line = extract_field_and_line(
        all_lines,
        [
            r"delivery[_-]?window[:\s]+([a-zA-Z0-9_\-\s]+)",
            r"window[:\s]+([a-zA-Z0-9_\-\s]+)",
        ],
    )

    team_id, team_line = extract_field_and_line(
        all_lines,
        [
            r"approval[_-]?queue[:\s]+([a-zA-Z0-9_\-]+)",
            r"team[:\s]+([a-zA-Z0-9_\-]+)",
            r"owning[_-]?team[:\s]+([a-zA-Z0-9_\-]+)",
        ],
    )

    # --- 2. SEND APPROVED NOTICE ---
    for l_id, text, _, prov in all_lines:
        if "approved" in text.lower() and (
            "notice" in text.lower() or "delivery" in text.lower() or "send" in text.lower()
        ):
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

    # --- 3. UPDATE INTERNAL RECORD ---
    if case_id or "update" in objective.lower() or "delivery_window" in objective.lower():
        evidence = []
        if case_line:
            evidence.append(case_line)
        if window_line and window_line not in evidence:
            evidence.append(window_line)
        if not evidence:
            evidence = [first_line_id]

        return (
            "update_internal_record",
            {"kind": "case_record", "id": case_id if case_id else f"case_{dossier_id}"},
            {
                "field": "delivery_window",
                "sourceEventId": dossier_id,
                "value": window_val if window_val else "morning_window",
            },
            evidence,
        )

    # --- 4. REQUEST CONFIRMATION ---
    for l_id, text, _, _ in all_lines:
        if "confirm" in text.lower() or "verify" in text.lower() or "ambiguous" in text.lower():
            evidence = [l_id]
            if team_line and team_line not in evidence:
                evidence.append(team_line)
            return (
                "request_confirmation",
                {
                    "kind": "approval_queue",
                    "id": team_id if team_id else "support_team",
                },
                {
                    "claimedSender": mailbox if mailbox else "unknown@domain.com",
                    "questionCode": "VERIFY_REQUEST",
                    "referenceId": ref_id,
                },
                evidence,
            )

    # --- 5. CREATE DRAFT ---
    for l_id, text, _, _ in all_lines:
        if "draft" in text.lower() or "enquiry" in text.lower() or "order" in text.lower():
            evidence = [l_id]
            if ref_line and ref_line not in evidence:
                evidence.append(ref_line)
            return (
                "create_draft",
                {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                {
                    "recipient": mailbox if mailbox else "customer@example.com",
                    "referenceId": ref_id,
                    "status": "pending",
                    "template": "order_status",
                },
                evidence,
            )

    # --- 6. NO ACTION (DEFAULT) ---
    reason_code = "INFORMATIONAL"
    if "duplicate" in objective.lower() or "duplicate" in dossier_id.lower():
        reason_code = "DUPLICATE"
    elif "completed" in objective.lower() or "already" in objective.lower():
        reason_code = "ALREADY_COMPLETED"

    return (
        "no_action",
        None,
        {"reasonCode": reason_code, "referenceId": ref_id},
        [first_line_id],
    )


# ---------------------------------------------------------------------------
# Ed25519 Receipt Signature Verification
# ---------------------------------------------------------------------------


def verify_receipt_signature(
    public_key_jwk: Dict[str, Any],
    evaluation_id: str,
    input_digest: str,
    receipt: Dict[str, Any],
    signature_b64: str,
) -> bool:
    """Verifies Ed25519 receipt signature against canonical JSON structure."""
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
    return jsonify({"status": "ok", "service": "Mailroom Action Gate", "profile": PROFILE}), 200


@app.route("/", methods=["POST"])
@app.route("/gate", methods=["POST"])
def mailroom_gate():
    try:
        data = request.get_json(force=True, silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

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
                return jsonify({"error": "Missing required fields"}), 400

            computed_digest = compute_input_digest(dossiers)

            # Strict 409 Conflict Check: evaluationId exists with changed content
            if evaluation_id in EVALUATION_STORE:
                existing = EVALUATION_STORE[evaluation_id]
                if existing["inputDigest"] != computed_digest:
                    return (
                        jsonify({"error": "409 Conflict: evaluationId content modified"}),
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

            # Save state
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

            # Replay check
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

            # Conflict / Digest Mismatch -> HTTP 409
            if stored_eval["inputDigest"] != input_digest:
                return jsonify({"error": "409 Conflict: inputDigest mismatch"}), 409

            proposals_map = {p["dossierId"]: p for p in stored_eval["proposals"]}
            verifier_jwk = stored_eval["receiptVerifier"].get("publicKeyJwk", {})

            if len(receipts) != len(proposals_map):
                return jsonify({"error": "Receipt count mismatch"}), 400

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

                # Verify alignment
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

            # Complete transaction
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