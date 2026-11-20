import hashlib
import threading


class CeremonyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _norm_holder(name):
    return name.strip().casefold()


class HsmKeyCeremony:
    def __init__(self, threshold, total_shares, ceremony_ttl=600):
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if threshold > total_shares:
            raise ValueError("threshold exceeds total shares")
        self.threshold = threshold
        self.total_shares = total_shares
        self.ceremony_ttl = ceremony_ttl
        self._lock = threading.Lock()
        self._ceremonies = {}
        self._seq = 0

    def _log(self, rec, event, now, **fields):
        self._seq += 1
        entry = {"event": event, "ts": now, "seq": self._seq}
        entry.update(fields)
        rec["events"].append(entry)

    def _get(self, ceremony_id):
        rec = self._ceremonies.get(ceremony_id.strip())
        if rec is None:
            raise CeremonyError("unknown_ceremony")
        return rec

    def open(self, ceremony_id, holders, now=0):
        cid = ceremony_id.strip()
        if not cid:
            raise CeremonyError("invalid_ceremony_id")
        if len(holders) != self.total_shares:
            raise CeremonyError("holder_count_mismatch")
        display = {}
        for name in holders:
            key = _norm_holder(name)
            if not key:
                raise CeremonyError("invalid_holder")
            if key in display:
                raise CeremonyError("duplicate_holder")
            display[key] = name.strip()
        with self._lock:
            if cid in self._ceremonies:
                raise CeremonyError("ceremony_exists")
            if any(r["state"] == "open" for r in self._ceremonies.values()):
                raise CeremonyError("ceremony_busy")
            slots = {}
            slot_by_key = {}
            for index, (key, name) in enumerate(display.items(), start=1):
                share_id = "share-%d" % index
                slots[name] = share_id
                slot_by_key[key] = share_id
            rec = {
                "id": cid,
                "state": "open",
                "opened_at": now,
                "expires_at": now + self.ceremony_ttl,
                "holders": display,
                "slots": slots,
                "slot_by_key": slot_by_key,
                "collected": {},
                "events": [],
                "key_handle": None,
                "abort_reason": None,
            }
            self._ceremonies[cid] = rec
            self._log(rec, "open", now, holders=sorted(display.values()))
            return {
                "ceremony_id": cid,
                "state": "open",
                "threshold": self.threshold,
                "total_shares": self.total_shares,
                "shares": dict(slots),
                "expires_at": rec["expires_at"],
            }

    def submit_share(self, ceremony_id, holder, share_id, now=0):
        cid = ceremony_id.strip()
        key = _norm_holder(holder)
        with self._lock:
            rec = self._get(cid)
            if rec["state"] != "open":
                raise CeremonyError("ceremony_closed")
            if len(rec["collected"]) >= self.threshold:
                raise CeremonyError("ceremony_closed")
            if now > rec["expires_at"]:
                raise CeremonyError("ceremony_expired")
            if key not in rec["holders"]:
                raise CeremonyError("unknown_holder")
            if key in rec["collected"]:
                raise CeremonyError("duplicate_holder")
            if rec["slot_by_key"][key] != share_id:
                raise CeremonyError("wrong_share")
            rec["collected"][key] = share_id
            self._log(
                rec, "share", now,
                holder=rec["holders"][key], share_id=share_id,
            )
            return {
                "ceremony_id": cid,
                "state": "open",
                "collected": len(rec["collected"]),
                "threshold": self.threshold,
            }

    def seal(self, ceremony_id, now=0):
        cid = ceremony_id.strip()
        with self._lock:
            rec = self._get(cid)
            if rec["state"] == "sealed":
                raise CeremonyError("already_sealed")
            if rec["state"] != "open":
                raise CeremonyError("ceremony_closed")
            if len(rec["collected"]) < self.threshold:
                raise CeremonyError("insufficient_shares")
            rec["state"] = "sealed"
            witnesses = sorted(rec["holders"][k] for k in rec["collected"])
            digest = hashlib.sha256(
                ("%s:%s" % (cid, ",".join(witnesses))).encode("utf-8")
            ).hexdigest()
            rec["key_handle"] = "hsm-key-%s" % digest[:16]
            self._log(rec, "seal", now, witnesses=list(witnesses))
            return {
                "ceremony_id": cid,
                "state": "sealed",
                "key_handle": rec["key_handle"],
                "witnesses": witnesses,
            }

    def abort(self, ceremony_id, reason, now=0):
        cid = ceremony_id.strip()
        if not reason or not reason.strip():
            raise CeremonyError("missing_reason")
        with self._lock:
            rec = self._get(cid)
            if rec["state"] == "aborted":
                raise CeremonyError("already_aborted")
            if rec["state"] != "open":
                raise CeremonyError("ceremony_closed")
            rec["state"] = "aborted"
            rec["abort_reason"] = reason.strip()
            self._log(rec, "abort", now, reason=rec["abort_reason"])
            return {
                "ceremony_id": cid,
                "state": "aborted",
                "reason": rec["abort_reason"],
            }

    def audit(self, ceremony_id):
        with self._lock:
            rec = self._get(ceremony_id)
            events = sorted(rec["events"], key=lambda e: (e["ts"], e["seq"]))
            return [dict(e) for e in events]
