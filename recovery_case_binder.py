import copy
import hashlib
import secrets
import threading


class RecoveryError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class RecoveryCaseBinder:
    _ACTIVE_STATES = frozenset({"open", "approved"})

    def __init__(self, ttl=86400, required_approvals=2):
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if required_approvals < 1:
            raise ValueError("required_approvals must be positive")

        self.ttl = ttl
        self.required_approvals = required_approvals
        self._lock = threading.RLock()
        self._cases = {}
        self._active_by_account = {}
        self._evidence_accounts = {}
        self._tokens = {}

    @staticmethod
    def _normalize_identity(value):
        if not isinstance(value, str):
            raise ValueError("identity must be a string")
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("identity must not be empty")
        return normalized

    @staticmethod
    def _normalize_digest(value):
        if not isinstance(value, str):
            raise ValueError("evidence digest must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("evidence digest must not be empty")
        return normalized

    @staticmethod
    def _token_digest(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _copy(value):
        return copy.deepcopy(value)

    def _generate_case_id(self):
        while True:
            case_id = "case-" + secrets.token_hex(16)
            if case_id not in self._cases:
                return case_id

    def _expire_case(self, case, now):
        if case["state"] in self._ACTIVE_STATES and now >= case["expires_at"]:
            case["state"] = "expired"
            case["expired_at"] = now
            self._active_by_account.pop(case["account_id"], None)
            return True
        return False

    def _get_case(self, case_id):
        try:
            return self._cases[case_id]
        except (KeyError, TypeError):
            raise RecoveryError("unknown_case") from None

    def _lookup_case(self, case_id, now):
        case = self._get_case(case_id)
        self._expire_case(case, now)
        return case

    def _bind_evidence(self, evidence_digest, account_id):
        bound_account = self._evidence_accounts.get(evidence_digest)
        if bound_account is not None and bound_account != account_id:
            raise RecoveryError("evidence_reused")
        self._evidence_accounts[evidence_digest] = account_id

    def open_case(self, account_id, requester, evidence, now=0):
        account_id = self._normalize_identity(account_id)
        requester = self._normalize_identity(requester)
        evidence_digest = self._normalize_digest(evidence)

        with self._lock:
            self._bind_evidence(evidence_digest, account_id)

            active_case_id = self._active_by_account.get(account_id)
            if active_case_id is not None:
                active_case = self._cases.get(active_case_id)
                if (
                    active_case is not None
                    and active_case["state"] in self._ACTIVE_STATES
                    and not self._expire_case(active_case, now)
                ):
                    return self._copy(active_case)
                self._active_by_account.pop(account_id, None)

            case_id = self._generate_case_id()
            case = {
                "case_id": case_id,
                "account_id": account_id,
                "requester": requester,
                "evidence_digest": evidence_digest,
                "state": "open",
                "created_at": now,
                "expires_at": now + self.ttl,
                "approvals": [],
                "denied_by": None,
                "denied_at": None,
                "completed_at": None,
                "expired_at": None,
                "token_digests": [],
            }
            self._cases[case_id] = case
            self._active_by_account[account_id] = case_id
            return self._copy(case)

    def approve(self, case_id, approver, now=0):
        approver = self._normalize_identity(approver)

        with self._lock:
            case = self._lookup_case(case_id, now)
            if case["state"] in {"denied", "completed"}:
                raise RecoveryError("case_closed")
            if case["state"] == "expired":
                raise RecoveryError("case_expired")
            if approver == case["requester"]:
                raise RecoveryError("self_approval")
            if approver in case["approvals"]:
                raise RecoveryError("duplicate_approval")

            case["approvals"].append(approver)
            if len(case["approvals"]) >= self.required_approvals:
                case["state"] = "approved"
            return self._copy(case)

    def deny(self, case_id, approver, now=0):
        approver = self._normalize_identity(approver)

        with self._lock:
            case = self._get_case(case_id)
            if case["state"] == "denied":
                return self._copy(case)
            if case["state"] == "completed":
                raise RecoveryError("case_closed")

            self._expire_case(case, now)
            if case["state"] == "expired":
                raise RecoveryError("case_expired")
            if approver == case["requester"]:
                raise RecoveryError("self_approval")

            case["state"] = "denied"
            case["denied_by"] = approver
            case["denied_at"] = now
            self._active_by_account.pop(case["account_id"], None)
            return self._copy(case)

    def issue_token(self, case_id, now=0):
        with self._lock:
            case = self._lookup_case(case_id, now)
            if case["state"] in {"denied", "completed"}:
                raise RecoveryError("case_closed")
            if case["state"] == "expired":
                raise RecoveryError("case_expired")
            if len(case["approvals"]) < self.required_approvals:
                raise RecoveryError("insufficient_approvals")

            token = secrets.token_urlsafe(32)
            token_digest = self._token_digest(token)
            self._tokens[token_digest] = {
                "case_id": case["case_id"],
                "issued_at": now,
                "expires_at": case["expires_at"],
                "used": False,
                "used_at": None,
            }
            case["token_digests"].append(token_digest)
            return {
                "case_id": case["case_id"],
                "token": token,
                "expires_at": case["expires_at"],
            }

    def complete(self, case_id, token, now=0):
        with self._lock:
            case = self._get_case(case_id)
            self._expire_case(case, now)
            if case["state"] == "expired":
                raise RecoveryError("case_expired")
            if case["state"] == "open":
                raise RecoveryError("not_approved")
            if case["state"] == "denied":
                raise RecoveryError("case_closed")

            if not isinstance(token, str) or not token:
                raise RecoveryError("invalid_token")

            token_digest = self._token_digest(token)
            token_record = self._tokens.get(token_digest)
            if case["state"] == "completed":
                if (
                    token_record is not None
                    and token_record["case_id"] == case["case_id"]
                    and token_record["used"]
                ):
                    raise RecoveryError("token_used")
                raise RecoveryError("case_closed")
            if token_record is None:
                raise RecoveryError("invalid_token")
            if token_record["case_id"] != case["case_id"]:
                raise RecoveryError("token_case_mismatch")
            if token_record["used"]:
                raise RecoveryError("token_used")

            token_record["used"] = True
            token_record["used_at"] = now
            case["state"] = "completed"
            case["completed_at"] = now

            for other_digest in case["token_digests"]:
                self._tokens[other_digest]["used"] = True
            self._active_by_account.pop(case["account_id"], None)
            return self._copy(case)

    def snapshot(self):
        with self._lock:
            return {
                "cases": self._copy(self._cases),
                "tokens": self._copy(self._tokens),
            }
