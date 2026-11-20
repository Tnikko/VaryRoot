class Diagnostic(ValueError):
    def __init__(self, field, message, code="invalid_bundle"):
        super().__init__(message)
        self.detail = {"code": code, "field": field, "message": message}


def require(ok, field, message, code="invalid_bundle"):
    if not ok:
        raise Diagnostic(field, message, code)


def fields(obj, names):
    require(isinstance(obj, dict), "$", "expected object")
    for name in names.split():
        require(name in obj, name, "required field missing")


def strings(values):
    return isinstance(values, list) and all(type(v) is str and v for v in values)
