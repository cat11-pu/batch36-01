import copy
import json
import re


class TenantScopeError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_IDENT_PART = re.compile(r"^[A-Za-z0-9_]+$")
_QUALIFIED_IDENT = re.compile(r"[A-Za-z0-9_]+\.[A-Za-z0-9_]+")
_FORBIDDEN_TOKENS = (";", "--", "/*", "*/")
_ALLOWED_OPS = {"=", "!=", "<>", "<", "<=", ">", ">=", "LIKE", "IN", "NOT IN"}
_TICKET_PREFIX = "INC-"


def _check_identifier(value):
    if not isinstance(value, str) or not value:
        raise TenantScopeError("unsafe_identifier")
    if any(token in value for token in _FORBIDDEN_TOKENS) or any(
        ch.isspace() for ch in value
    ):
        raise TenantScopeError("unsafe_identifier")
    parts = value.split(".")
    if len(parts) > 2 or any(not _IDENT_PART.match(part) for part in parts):
        raise TenantScopeError("unsafe_identifier")
    return value


def _check_raw_fragment(value):
    if not isinstance(value, str) or not value.strip():
        raise TenantScopeError("unsafe_identifier")
    if any(token in value for token in _FORBIDDEN_TOKENS):
        raise TenantScopeError("unsafe_identifier")
    return value


class TenantScopePlanner:
    def __init__(self, tables, shared_tables=()):
        if not isinstance(tables, dict):
            raise TenantScopeError("bad_query")
        self._tables = dict(tables)
        self._shared = set(shared_tables)
        for name in self._tables:
            _check_identifier(name)
        for name in self._shared:
            _check_identifier(name)

    def _tenant_column(self, table):
        info = self._tables.get(table)
        if info is None:
            return None
        column = info.get("tenant_column")
        return column if column else None

    def _is_known_table(self, table):
        if table not in self._tables:
            return False
        if self._tenant_column(table):
            return True
        return table in self._shared

    def plan(self, tenant, query):
        if not isinstance(tenant, str) or not tenant.strip():
            raise TenantScopeError("bad_tenant")
        if not isinstance(query, dict):
            raise TenantScopeError("bad_query")
        if query.get("union") or query.get("unions"):
            raise TenantScopeError("unsupported_union")

        cross_tenant = bool(query.get("cross_tenant"))
        audit_ticket = query.get("audit_ticket")
        if cross_tenant and not (
            isinstance(audit_ticket, str) and audit_ticket.startswith(_TICKET_PREFIX)
        ):
            raise TenantScopeError("cross_tenant_forbidden")

        select = query.get("select")
        if not isinstance(select, list) or not select:
            raise TenantScopeError("bad_query")
        select = [_check_identifier(col) for col in select]

        base = query.get("from")
        if not isinstance(base, str):
            raise TenantScopeError("bad_query")
        base = _check_identifier(base)
        if "." in base:
            raise TenantScopeError("unsafe_identifier")

        joins = query.get("joins", [])
        where = query.get("where", [])
        if not isinstance(joins, list) or not isinstance(where, list):
            raise TenantScopeError("bad_query")

        if not self._is_known_table(base):
            raise TenantScopeError("unknown_table")

        involved = [base]
        parsed_joins = []
        for join in joins:
            if not isinstance(join, dict):
                raise TenantScopeError("bad_query")
            table = join.get("table")
            on = join.get("on")
            if not isinstance(table, str):
                raise TenantScopeError("bad_query")
            table = _check_identifier(table)
            if "." in table:
                raise TenantScopeError("unsafe_identifier")
            if not self._is_known_table(table):
                raise TenantScopeError("unknown_table")
            _check_raw_fragment(on)
            involved.append(table)
            parsed_joins.append((table, on))

        participant = set(involved)
        for table, on in parsed_joins:
            for ref in _QUALIFIED_IDENT.findall(on):
                ref_table = ref.split(".", 1)[0]
                if ref_table not in participant:
                    raise TenantScopeError("unknown_table")

        tenant_columns = {
            name: self._tenant_column(name)
            for name in involved
            if self._tenant_column(name)
        }

        parsed_where = []
        for cond in where:
            if not isinstance(cond, dict):
                raise TenantScopeError("bad_query")
            column = cond.get("column")
            op = cond.get("op")
            value = cond.get("value")
            column = _check_identifier(column)
            if not isinstance(op, str) or op.upper() not in _ALLOWED_OPS:
                raise TenantScopeError("bad_query")
            if isinstance(value, (dict, list, tuple, set)):
                raise TenantScopeError("bad_query")
            col_name = column.split(".")[-1]
            for tcol in tenant_columns.values():
                if col_name == tcol:
                    raise TenantScopeError("tenant_override")
            parsed_where.append((column, op.upper(), copy.deepcopy(value)))

        sql_parts = ["SELECT " + ", ".join(select), "FROM " + base]
        for table, on in parsed_joins:
            on_clause = on
            join_tcol = tenant_columns.get(table)
            if join_tcol:
                other = None
                for ref in _QUALIFIED_IDENT.findall(on):
                    ref_table = ref.split(".", 1)[0]
                    if ref_table != table and ref_table in tenant_columns:
                        other = ref_table
                        break
                if other is None and base in tenant_columns and base != table:
                    other = base
                if other is not None:
                    on_clause += (
                        " AND "
                        + table
                        + "."
                        + join_tcol
                        + " = "
                        + other
                        + "."
                        + tenant_columns[other]
                    )
            sql_parts.append("JOIN " + table + " ON " + on_clause)

        predicates = []
        params = []
        if not cross_tenant:
            for name in involved:
                tcol = tenant_columns.get(name)
                if tcol:
                    predicates.append(name + "." + tcol + " = ?")
                    params.append(tenant)
        for column, op, value in parsed_where:
            predicates.append(column + " " + op + " ?")
            params.append(value)
        if predicates:
            sql_parts.append("WHERE " + " AND ".join(predicates))
        sql = "\n".join(sql_parts)

        cache_payload = {
            "tenant": tenant,
            "cross_tenant": cross_tenant,
            "audit_ticket": audit_ticket if cross_tenant else None,
            "select": select,
            "from": base,
            "joins": [{"table": t, "on": o} for t, o in parsed_joins],
            "where": [
                {"column": c, "op": o, "value": v} for c, o, v in parsed_where
            ],
        }
        cache_key = tenant + "|" + json.dumps(
            cache_payload, sort_keys=True, default=str
        )

        return {
            "sql": sql,
            "params": params,
            "cache_key": cache_key,
            "tables": list(involved),
            "cross_tenant": cross_tenant,
        }
