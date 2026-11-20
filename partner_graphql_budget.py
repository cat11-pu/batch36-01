class BudgetError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PartnerQueryBudget:
    WINDOW_SECONDS = 60
    PAGINATION_ARGS = ("first", "last")

    def __init__(self, max_depth=8, max_cost=1000, max_aliases=20, page_factor=10, partner_quota=5000):
        self.max_depth = max_depth
        self.max_cost = max_cost
        self.max_aliases = max_aliases
        self.page_factor = page_factor
        self.partner_quota = partner_quota
        self._windows = {}
        self._charged = 0
        self._rejected = 0

    def measure(self, document):
        if document.get("operation") != "query":
            raise BudgetError("operation_not_allowed")

        stats = {"depth": 0, "fields": 0}
        alias_targets = {}
        fragments = document.get("fragments") or {}
        level_marks = {}
        cost = self._walk(
            document.get("selections") or [],
            1,
            set(),
            level_marks,
            fragments,
            alias_targets,
            stats,
        )

        alias_count = len(alias_targets)
        if alias_count > self.max_aliases:
            raise BudgetError("too_many_aliases")
        if stats["depth"] > self.max_depth:
            raise BudgetError("too_deep")
        if cost > self.max_cost:
            raise BudgetError("cost_exceeded")

        return {
            "depth": stats["depth"],
            "cost": cost,
            "fields": stats["fields"],
            "aliases": alias_count,
        }

    def charge(self, partner, document, now=0):
        try:
            measured = self.measure(document)
        except BudgetError:
            self._rejected += 1
            raise

        window = self._windows.get(partner)
        if window is None or now - window["start"] >= self.WINDOW_SECONDS:
            window = {"start": now, "used": 0}
            self._windows[partner] = window

        cost = measured["cost"]
        if window["used"] + cost > self.partner_quota:
            self._rejected += 1
            raise BudgetError("quota_exceeded")

        window["used"] += cost
        self._charged += 1
        return {"remaining": self.partner_quota - window["used"]}

    def snapshot(self):
        return {"charged": self._charged, "rejected": self._rejected}

    def _walk(self, selections, depth, active_fragments, level_marks, fragments, alias_targets, stats):
        total = 0
        for node in selections:
            if "spread" in node:
                total += self._expand_spread(
                    node["spread"],
                    depth,
                    active_fragments,
                    level_marks,
                    fragments,
                    alias_targets,
                    stats,
                )
                continue

            field = node["field"]
            if field.startswith("_"):
                raise BudgetError("introspection")

            stats["fields"] += 1
            stats["depth"] = max(stats["depth"], depth)

            alias = node.get("alias")
            if alias is not None:
                target = alias_targets.get(alias)
                if target is not None and target != field:
                    raise BudgetError("alias_conflict")
                alias_targets.setdefault(alias, field)

            multiplier = 1
            for arg_name in self.PAGINATION_ARGS:
                if arg_name in (node.get("args") or {}):
                    multiplier *= self._page_value(node["args"][arg_name])

            child_cost = 0
            sub_selections = node.get("selections")
            if sub_selections:
                child_cost = self._walk(
                    sub_selections,
                    depth + 1,
                    active_fragments,
                    level_marks,
                    fragments,
                    alias_targets,
                    stats,
                )
            total += 1 + multiplier * child_cost
        return total

    def _expand_spread(
        self, name, depth, active_fragments, level_marks, fragments, alias_targets, stats
    ):
        if name not in fragments:
            raise BudgetError("unknown_fragment")
        if name in active_fragments:
            raise BudgetError("fragment_cycle")

        marked = level_marks.setdefault(depth, set())
        if name in marked:
            return 0
        marked.add(name)

        active_fragments.add(name)
        try:
            return self._walk(
                fragments[name].get("selections") or [],
                depth,
                active_fragments,
                level_marks,
                fragments,
                alias_targets,
                stats,
            )
        finally:
            active_fragments.discard(name)

    def _page_value(self, value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise BudgetError("bad_pagination")
        if value < 1 or value > self.page_factor:
            raise BudgetError("bad_pagination")
        return value
