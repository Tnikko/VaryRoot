import cpp

// Role rules are scoped to the two registered Step 04 fixtures.
string operation(ArrayExpr e) {
  e = any(AssignOperation a).getLValue() and result = "read_write"
  or
  e = any(AssignExpr a).getLValue() and result = "write"
  or
  not e = any(Assignment a).getLValue() and result = "read"
}

from ArrayExpr e, Location loc, string path
where
  loc = e.getLocation() and path = loc.getFile().getRelativePath() and
  path in ["accesses.cpp", "reviewed.c"]
select path, loc.getStartLine(), loc.getStartColumn(), loc.getEndLine(), loc.getEndColumn(),
  operation(e), count(ArrayExpr other | other.getLocation() = loc and operation(other) = operation(e))
