import copy
import threading


class CounterWatchError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class CounterCloneWatch:
    def __init__(self, jump_threshold=1000):
        self.jump_threshold = jump_threshold
        self._credentials = {}
        self._lock = threading.RLock()

    @staticmethod
    def _require_id(value, field):
        if not isinstance(value, str) or not value.strip():
            raise CounterWatchError("invalid_argument")

    @staticmethod
    def _require_counter(value):
        if type(value) is not int or value < 0:
            raise CounterWatchError("invalid_argument")

    def register(self, credential_id, device_id, counter=0, now=0):
        self._require_id(credential_id, "credential_id")
        self._require_id(device_id, "device_id")
        self._require_counter(counter)
        with self._lock:
            if credential_id in self._credentials:
                raise CounterWatchError("credential_exists")
            record = {
                "credential_id": credential_id,
                "device_id": device_id,
                "state": "active",
                "last_counter": counter,
                "alerts": [],
            }
            self._credentials[credential_id] = record
            return copy.deepcopy(record)

    def observe(self, credential_id, device_id, counter, signature_ok, now=0):
        self._require_id(credential_id, "credential_id")
        self._require_id(device_id, "device_id")
        self._require_counter(counter)
        with self._lock:
            record = self._credentials.get(credential_id)
            if record is None:
                raise CounterWatchError("unknown_credential")
            if record["state"] == "quarantined":
                raise CounterWatchError("credential_quarantined")
            if record["device_id"] != device_id:
                raise CounterWatchError("device_mismatch")
            if not signature_ok:
                raise CounterWatchError("bad_signature")

            baseline = record["last_counter"]
            accepted = True
            if counter == 0:
                # Authenticators without counter support: keep the baseline untouched.
                pass
            elif counter <= baseline:
                record["state"] = "quarantined"
                raise CounterWatchError("clone_detected")
            else:
                if counter - baseline > self.jump_threshold:
                    record["alerts"].append({
                        "type": "counter_jump",
                        "time": now,
                        "at": now,
                        "old_baseline": baseline,
                        "counter": counter,
                    })
                record["last_counter"] = counter
            return {
                "accepted": accepted,
                "credential_id": credential_id,
                "last_counter": record["last_counter"],
                "state": record["state"],
            }

    def status(self, credential_id):
        with self._lock:
            record = self._credentials.get(credential_id)
            if record is None:
                raise CounterWatchError("unknown_credential")
            return {
                "credential_id": record["credential_id"],
                "device_id": record["device_id"],
                "state": record["state"],
                "last_counter": record["last_counter"],
                "alerts": copy.deepcopy(record["alerts"]),
            }

    def recover(self, credential_id, device_id, counter, now=0):
        self._require_id(credential_id, "credential_id")
        self._require_id(device_id, "device_id")
        self._require_counter(counter)
        with self._lock:
            record = self._credentials.get(credential_id)
            if record is None:
                raise CounterWatchError("unknown_credential")
            if record["device_id"] != device_id:
                raise CounterWatchError("device_mismatch")
            if counter < record["last_counter"]:
                raise CounterWatchError("baseline_regression")
            record["state"] = "active"
            record["last_counter"] = counter
            return self.status(credential_id)

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self._credentials)
