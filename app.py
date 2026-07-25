import base64
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, Response, jsonify, request

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
    """Computes SHA-256 hex digest over UTF-8 bytes of dossiers array encoded as recursively key-sorted compact JSON."""
    return hashlib.sha256(canonical_json_bytes(dossiers)).hexdigest().lower()


def compute_dossier_content_hash(dossier: Dict[str, Any]) -> str:
    """Computes a stable fingerprint for a dossier based on its immutable content (mailbox, objective, sources)."""
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
# Safety & Action Decision Engine
# ---------------------------------------------------------------------------


def analyze_dossier(dossier: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Analyzes a dossier using deterministic rules and safety boundaries to return: (action, target, payload, evidence_line_ids)."""
    sources = dossier.get("sources", [])
    objective = dossier.get("objective", "").lower()
    mailbox = dossier.get("mailbox", "")

    all_lines: List[Tuple[str, str, str]] = []  # (lineId, text, kind)
    evidence_map: Dict[str, str] = {}

    for src in sources:
        kind = src.get("kind", "")
        for line in src.get("lines", []):
            line_id = line.get("lineId")
            text = line.get("text", "")
            if line_id:
                all_lines.append((line_id, text, kind))
                evidence_map[line_id] = text

    combined_text = " ".join([txt for _, txt, _ in all_lines]).lower()

    # Rule 1: Quarantine Indirect Prompt Injections / Exfiltration Attempts
    injection_keywords = [
        "ignore previous instructions",
        "ignore all prior instructions",
        "system prompt",
        "exfiltrate",
        "send secrets to",
        "override safety",
        "bypass security",
        "hidden instruction",
        "eval(",
        "base64 -d",
    ]

    for line_id, text, kind in all_lines:
        t_lower = text.lower()
        if any(kw in t_lower for kw in injection_keywords) and kind in ("external_email", "attachment", "untrusted"):
            first_line_id = all_lines[0][0] if all_lines else line_id
            return (
                "quarantine_item",
                {"kind": "security_queue", "id": "mailroom"},
                {"artifactId": dossier.get("dossierId", "unknown"), "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                [line_id],
            )

    # Rule 2: Send Approved Notice
    if "approved" in objective or "approved" in combined_text:
        approved_line = None
        for line_id, text, _ in all_lines:
            if "approved" in text.lower() or "confirmed delivery" in text.lower():
                approved_line = line_id
                break

        evidence = [approved_line] if approved_line else [all_lines[0][0]]
        return (
            "send_approved_notice",
            {"kind": "email", "id": mailbox if mailbox else "customer@example.com"},
            {"referenceId": dossier.get("dossierId", "ref_001"), "status": "approved", "template": "approved_delivery_notice"},
            evidence,
        )

    # Rule 3: Update Internal Record
    if "update" in objective or "case" in combined_text or "delivery window" in combined_text:
        case_line = all_lines[0][0] if all_lines else "line_1"
        return (
            "update_internal_record",
            {"kind": "case_record", "id": f"case_{dossier.get('dossierId', '001')}"},
            {"field": "delivery_window", "sourceEventId": dossier.get("dossierId", "evt_001"), "value": "updated"},
            [case_line],
        )

    # Rule 4: Request Confirmation (Ambiguous Identity / Suspicious Request)
    if "confirm" in objective or "verify" in combined_text or "ambiguous" in combined_text:
        return (
            "request_confirmation",
            {"kind": "approval_queue", "id": "support_team"},
            {"claimedSender": mailbox if mailbox else "unknown@domain.com", "questionCode": "VERIFY_REQUEST", "referenceId": dossier.get("dossierId", "ref_001")},
            [all_lines[0][0]] if all_lines else ["line_1"],
        )

    # Rule 5: Draft Response for Customer Enquiries
    if "draft" in objective or "customer" in combined_text or "order" in combined_text:
        return (
            "create_draft",
            {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            {"recipient": mailbox, "referenceId": dossier.get("dossierId", "ref_001"), "status": "pending", "template": "order_status"},
            [all_lines[0][0]] if all_lines else ["line_1"],
        )

    # Rule 6: Default / No Action
    default_line = all_lines[0][0] if all_lines else "line_1"
    return (
        "no_action",
        None,
        {"reasonCode": "INFORMATIONAL", "referenceId": dossier.get("dossierId", "ref_001")},
        [default_line],
    )


# ---------------------------------------------------------------------------
# Receipt Verification (Ed25519)
# ---------------------------------------------------------------------------


def verify_receipt_signature(
    public_key_jwk: Dict[str, Any],
    evaluation_id: str,
    input_digest: str,
    receipt: Dict[str, Any],
    signature_b64: str,
) -> bool:
    """Imports Ed25519 public key JWK and verifies signature over normalized JSON receipt envelope."""
    try:
        x_b64 = public_key_jwk.get("x", "")
        # Add base64 padding if needed
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
# Flask HTTP Endpoints
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
            return jsonify({"error": f"Unsupported profile '{profile}'"}), 400

        # -------------------------------------------------------------------
        # OPERATION 1: PROPOSE
        # -------------------------------------------------------------------
        if operation == "propose":
            evaluation_id = data.get("evaluationId")
            dossiers = data.get("dossiers", [])
            receipt_verifier = data.get("receiptVerifier", {})

            if not evaluation_id or not dossiers:
                return jsonify({"error": "Missing evaluationId or dossiers"}), 400

            computed_digest = compute_input_digest(dossiers)

            # Check if evaluationId exists with changed content (HTTP 409)
            if evaluation_id in EVALUATION_STORE:
                existing = EVALUATION_STORE[evaluation_id]
                if existing["inputDigest"] != computed_digest:
                    return jsonify({"error": "evaluationId exists with different input content"}), 409
                # Replay exact cached response
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

            for idx, dossier in enumerate(dossiers):
                d_id = dossier.get("dossierId")
                if not d_id or d_id in seen_dossier_ids:
                    return jsonify({"error": f"Duplicate or missing dossierId: {d_id}"}), 400
                seen_dossier_ids.add(d_id)

                # Cache lookup by canonical content hash
                content_hash = compute_dossier_content_hash(dossier)

                if content_hash in DOSSIER_CACHE:
                    cached_proposal = DOSSIER_CACHE[content_hash]
                    # Preserve proposal structure with current dossierId
                    prop = {
                        "dossierId": d_id,
                        "callId": cached_proposal["callId"],
                        "action": cached_proposal["action"],
                        "target": cached_proposal["target"],
                        "payload": cached_proposal["payload"],
                        "evidence": cached_proposal["evidence"],
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

            # Store state for commit phase
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
        # OPERATION 2: COMMIT
        # -------------------------------------------------------------------
        elif operation == "commit":
            evaluation_id = data.get("evaluationId")
            input_digest = data.get("inputDigest")
            receipts = data.get("receipts", [])

            if not evaluation_id or evaluation_id not in EVALUATION_STORE:
                return jsonify({"error": f"Unknown evaluationId: {evaluation_id}"}), 400

            stored_eval = EVALUATION_STORE[evaluation_id]

            # Replay commit check
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

                # Verify proposalDigest, action, and callId alignment
                if (
                    receipt.get("proposalDigest") != expected_digest
                    or receipt.get("callId") != proposal["callId"]
                    or receipt.get("action") != proposal["action"]
                ):
                    return jsonify({"error": f"Receipt payload mismatch for dossier {d_id}"}), 400

                # Verify Ed25519 Signature
                is_valid_sig = verify_receipt_signature(
                    verifier_jwk,
                    evaluation_id,
                    input_digest,
                    receipt,
                    sig_b64,
                )

                if not is_valid_sig:
                    return jsonify({"error": f"Invalid signature on receipt for dossier {d_id}"}), 400

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

            # Store completed outcomes
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