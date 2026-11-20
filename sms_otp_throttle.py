import hashlib
import ipaddress
import math
import threading


_E164_MIN_DIGITS = 8
_E164_MAX_DIGITS = 15
_DAILY_WINDOW = 24 * 60 * 60


class SmsThrottleError(ValueError):
    def __init__(self, code, retry_after=0):
        retry_after = max(1, int(math.ceil(retry_after)))
        super().__init__(f"{code} (retry_after={retry_after}s)")
        self.code = code
        self.retry_after = retry_after


def _extract_digits(value, *, name, min_digits, max_digits):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")

    text = value.strip()
    if not text:
        raise ValueError(f"{name} is empty")

    if text.startswith("+"):
        text = text[1:]
    if "+" in text:
        raise ValueError(f"invalid {name}")

    digits = []
    for char in text:
        if "0" <= char <= "9":
            digits.append(char)
        elif char in " -()" or char.isspace():
            continue
        else:
            raise ValueError(f"invalid {name}")

    if not min_digits <= len(digits) <= max_digits:
        raise ValueError(f"invalid {name}")
    if digits[0] == "0":
        raise ValueError(f"invalid {name}")
    return "".join(digits)


def _normalize_phone(phone):
    digits = _extract_digits(
        phone,
        name="phone number",
        min_digits=_E164_MIN_DIGITS,
        max_digits=_E164_MAX_DIGITS,
    )
    return "+" + digits


def _normalize_prefix(prefix):
    digits = _extract_digits(
        prefix,
        name="blocked prefix",
        min_digits=1,
        max_digits=_E164_MAX_DIGITS,
    )
    return "+" + digits


def _normalize_ip(ip):
    if not isinstance(ip, str):
        raise ValueError("ip must be a string")
    text = ip.strip()
    if not text:
        raise ValueError("ip is empty")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError("invalid ip address") from exc

    family = "ipv4" if address.version == 4 else "ipv6"
    return family, str(address)


def _bucket_id(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _prune(times, cutoff):
    while times and times[0] <= cutoff:
        times.pop(0)


class SmsOtpThrottle:
    def __init__(
        self,
        per_phone=3,
        per_ip=10,
        global_limit=100,
        window=3600,
        cooldown=60,
        daily_cap=10,
        blocked_prefixes=(),
    ):
        self.per_phone = self._positive_int("per_phone", per_phone)
        self.per_ip = self._positive_int("per_ip", per_ip)
        self.global_limit = self._positive_int("global_limit", global_limit)
        self.window = self._positive_int("window", window)
        self.daily_cap = self._positive_int("daily_cap", daily_cap)

        self.cooldown = max(0, int(cooldown))

        if isinstance(blocked_prefixes, str):
            blocked_prefixes = (blocked_prefixes,)
        if blocked_prefixes is None:
            blocked_prefixes = ()
        self.blocked_prefixes = tuple(
            _normalize_prefix(prefix) for prefix in blocked_prefixes
        )

        self._phones = {}
        self._ips = {"ipv4": {}, "ipv6": {}}
        self._global = []
        self._daily = []
        self._last_send = {}
        self._last_seen = None
        self._lock = threading.RLock()

    @staticmethod
    def _positive_int(name, value):
        if isinstance(value, bool):
            raise ValueError(f"{name} must be a positive integer")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a positive integer") from exc
        if value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def _validate_now(now):
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            raise ValueError("now must be a number")
        if not math.isfinite(now) or now < 0:
            raise ValueError("now must be a finite non-negative number")
        return now

    @staticmethod
    def _retry_for(times, window, now):
        return max(1, int(math.ceil(times[0] + window - now)))

    def _prune_all(self, now):
        phone_cutoff = now - self.window
        for key in list(self._phones):
            _prune(self._phones[key], phone_cutoff)
            if not self._phones[key]:
                del self._phones[key]

        for family in self._ips.values():
            for key in list(family):
                _prune(family[key], phone_cutoff)
                if not family[key]:
                    del family[key]

        _prune(self._global, now - self.window)
        _prune(self._daily, now - _DAILY_WINDOW)

        if self._last_send:
            for key in list(self._last_send):
                if now >= self._last_send[key] + self.cooldown:
                    del self._last_send[key]

    def request(self, phone, ip, now=0):
        normalized_phone = _normalize_phone(phone)
        family, normalized_ip = _normalize_ip(ip)
        now = self._validate_now(now)
        phone_key = _bucket_id(normalized_phone)
        ip_key = _bucket_id(f"{family}:{normalized_ip}")

        with self._lock:
            if self._last_seen is not None and now < self._last_seen:
                raise SmsThrottleError("clock_regression", 1)
            self._last_seen = now
            self._prune_all(now)

            if any(
                normalized_phone.startswith(prefix)
                for prefix in self.blocked_prefixes
            ):
                raise SmsThrottleError("blocked_number", 1)

            last_send = self._last_send.get(phone_key)
            if self.cooldown > 0 and last_send is not None:
                remaining = last_send + self.cooldown - now
                if remaining > 0:
                    raise SmsThrottleError("cooldown", remaining)

            phone_times = self._phones.get(phone_key, [])
            if len(phone_times) >= self.per_phone:
                raise SmsThrottleError(
                    "phone_limit",
                    self._retry_for(phone_times, self.window, now),
                )

            ip_times = self._ips[family].get(ip_key, [])
            if len(ip_times) >= self.per_ip:
                raise SmsThrottleError(
                    "ip_limit",
                    self._retry_for(ip_times, self.window, now),
                )

            if len(self._daily) >= self.daily_cap:
                raise SmsThrottleError(
                    "daily_cap",
                    self._retry_for(self._daily, _DAILY_WINDOW, now),
                )

            if len(self._global) >= self.global_limit:
                raise SmsThrottleError(
                    "global_limit",
                    self._retry_for(self._global, self.window, now),
                )

            self._phones.setdefault(phone_key, []).append(now)
            self._ips[family].setdefault(ip_key, []).append(now)
            self._global.append(now)
            self._daily.append(now)
            if self.cooldown > 0:
                self._last_send[phone_key] = now

        return {"allowed": True, "phone": normalized_phone}

    @staticmethod
    def _snapshot_bucket(times):
        return {"count": len(times), "times": list(times)}

    def snapshot(self):
        with self._lock:
            if self._last_seen is not None:
                self._prune_all(self._last_seen)

            phones = {
                key: self._snapshot_bucket(times)
                for key, times in self._phones.items()
            }
            ips = {
                family: {
                    key: self._snapshot_bucket(times)
                    for key, times in buckets.items()
                }
                for family, buckets in self._ips.items()
            }
            return {
                "phones": phones,
                "ips": ips,
                "global": self._snapshot_bucket(self._global),
                "daily": self._snapshot_bucket(self._daily),
                "cooldowns": dict(self._last_send),
                "last_seen": self._last_seen,
            }
