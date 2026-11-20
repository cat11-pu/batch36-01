class KubeRBACError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class KubeRBACResolver:
    def __init__(self, roles, cluster_roles, role_bindings, cluster_role_bindings):
        pass

    def allowed(self, subject, verb, resource=None, namespace=None, name=None,
                subresource=None, non_resource_url=None, api_group=""):
        return None

    def explain(self, subject, verb, resource=None, namespace=None, name=None,
                subresource=None, non_resource_url=None, api_group=""):
        return None
