import copy


class ChainError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


KNOWN_CRITICAL_EXTENSIONS = frozenset(
    [
        "keyUsage",
        "basicConstraints",
        "subjectAltName",
        "nameConstraints",
        "certificatePolicies",
        "extKeyUsage",
        "policyMappings",
        "policyConstraints",
        "inhibitAnyPolicy",
        "cRLDistributionPoints",
        "freshestCRL",
        "authorityKeyIdentifier",
        "subjectKeyIdentifier",
    ]
)


def _default_verify_link(child, parent):
    return child.get("issuer_spki", "") == parent.get("spki", "")


def _dns_matches(name, constraint):
    if constraint.startswith("."):
        suffix = constraint[1:]
        return name.endswith("." + suffix)
    if "." in constraint:
        return name == constraint or name.endswith("." + constraint)
    return name == constraint


class ChainBuilder:
    def __init__(self, anchors, max_depth=4, verify_link=None):
        self._anchors = list(anchors)
        self._max_depth = max_depth
        self._verify_link = verify_link or _default_verify_link
        self._audit = None

    def build(self, leaf, intermediates, now, purpose="serverAuth"):
        self._audit = {
            "leaf": copy.deepcopy(leaf),
            "attempts": [],
            "rejected": [],
            "result": None,
        }

        self._check_cert(leaf, now, purpose, require_ca=False)

        intermediates_by_spki = {}
        for cert in intermediates:
            intermediates_by_spki.setdefault(cert["spki"], []).append(cert)
        # BFS over paths: every path is a leaf-first list.  A fingerprint is
        # expanded at most once per build so the search terminates even for
        # long or cyclic graphs without recursive calls.
        queue = [[leaf]]
        expanded = set()
        untrusted_anchor = None

        while queue:
            path = queue.pop(0)
            current = path[-1]

            if current["fingerprint"] in expanded:
                continue
            expanded.add(current["fingerprint"])
            self._audit["attempts"].append(
                [cert["fingerprint"] for cert in path]
            )

            candidates = []
            for anchor in self._anchors:
                if anchor["subject"] != current["issuer"]:
                    continue
                if not self._verify_link(current, anchor):
                    untrusted_anchor = untrusted_anchor or {
                        "fingerprint": anchor["fingerprint"],
                        "code": "untrusted_anchor",
                    }
                    continue
                candidates.append(("anchor", anchor))

            for parent in intermediates_by_spki.get(
                current.get("issuer_spki", ""), []
            ):
                if parent["fingerprint"] in {
                    cert["fingerprint"] for cert in path
                }:
                    self._audit["rejected"].append(
                        {
                            "fingerprint": parent["fingerprint"],
                            "code": "loop",
                        }
                    )
                    continue
                if not self._verify_link(current, parent):
                    self._audit["rejected"].append(
                        {
                            "fingerprint": parent["fingerprint"],
                            "code": "bad_link",
                        }
                    )
                    continue
                candidates.append(("intermediate", parent))

            candidates.sort(key=lambda item: item[1]["fingerprint"])

            for kind, parent in candidates:
                next_path = path + [parent]
                if kind == "anchor":
                    try:
                        self._validate_complete_path(next_path, now, purpose)
                    except ChainError as error:
                        self._audit["rejected"].append(
                            {
                                "fingerprint": parent["fingerprint"],
                                "code": error.code,
                            }
                        )
                        continue
                    return self._success(next_path, parent)

                intermediates_in_path = len(next_path) - 1
                if intermediates_in_path > self._max_depth:
                    self._audit["rejected"].append(
                        {
                            "fingerprint": parent["fingerprint"],
                            "code": "chain_too_deep",
                        }
                    )
                    continue
                try:
                    self._check_cert(parent, now, purpose, require_ca=True)
                except ChainError as error:
                    self._audit["rejected"].append(
                        {
                            "fingerprint": parent["fingerprint"],
                            "code": error.code,
                        }
                    )
                    continue
                queue.append(next_path)

        if untrusted_anchor is not None:
            self._audit["rejected"].append(dict(untrusted_anchor))
            raise ChainError("untrusted_anchor")

        loop_rejections = [
            item for item in self._audit["rejected"] if item["code"] == "loop"
        ]
        if loop_rejections:
            raise ChainError("loop")
        if self._audit["rejected"]:
            raise ChainError(self._audit["rejected"][0]["code"])
        raise ChainError("no_path")

    def audit(self):
        return copy.deepcopy(self._audit)

    def _success(self, path, anchor):
        result = {
            "chain": [copy.deepcopy(cert) for cert in path],
            "anchor": anchor["fingerprint"],
            "path_len": len(path) - 2,
        }
        self._audit["result"] = copy.deepcopy(result)
        return result

    def _check_cert(self, cert, now, purpose, require_ca):
        if require_ca and not cert.get("is_ca", False):
            raise ChainError("not_ca")
        if now < cert["not_before"]:
            raise ChainError("not_yet_valid")
        if now >= cert["not_after"]:
            raise ChainError("expired")
        eku = cert.get("eku") or []
        if eku and purpose not in eku:
            raise ChainError("bad_eku")
        for extension in cert.get("critical_ext", []):
            if extension not in KNOWN_CRITICAL_EXTENSIONS:
                raise ChainError("unknown_critical")

    def _validate_complete_path(self, path, now, purpose):
        for index, cert in enumerate(path):
            is_anchor = index == len(path) - 1
            require_ca = 0 < index and not is_anchor
            self._check_cert(cert, now, purpose, require_ca=require_ca)

        for index, cert in enumerate(path):
            limit = cert.get("path_len")
            if limit is None:
                continue
            subordinate_cas = sum(
                1
                for other in path[:index]
                if other.get("is_ca", False)
            )
            if subordinate_cas > limit:
                raise ChainError("path_len_exceeded")

        for index, ca_cert in enumerate(path):
            constraints = ca_cert.get("name_constraints") or {}
            permitted = constraints.get("permitted") or []
            excluded = constraints.get("excluded") or []
            if not permitted and not excluded:
                continue
            for subject in path[:index]:
                dns_names = subject.get("dns_names") or []
                for name in dns_names:
                    if any(_dns_matches(name, entry) for entry in excluded):
                        raise ChainError("name_constraint")
                    if permitted and not any(
                        _dns_matches(name, entry) for entry in permitted
                    ):
                        raise ChainError("name_constraint")
