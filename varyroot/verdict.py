"""Finite-domain evidence classification for an unambiguous registered access."""
def classify(declared,rows,*,normal_inputs):
    if not normal_inputs or not set(normal_inputs)<=set(declared):
        raise ValueError('missing normal input definition')
    ids=[r["input_id"] for r in rows]
    if (not declared or len(set(declared))!=len(declared) or len(set(ids))!=len(ids)
            or not set(ids)<=set(declared)):
        raise ValueError("domain or observation identity mismatch")
    for row in rows:
        event=row["event"]
        if event not in {"used","blocked","violation","no_access"} or row["accesses"]!=int(event=="used"):
            raise ValueError("inconsistent observation")
        if event=="used" and ("reference_value" not in row or row["reference_value"]!=row["value"]):
            raise ValueError("normal return unconfirmed")
    missing=sorted(set(declared)-set(ids))
    normal=[r["input_id"] for r in rows if r["event"]=="used" and r["input_id"] in normal_inputs]
    violations=[r["input_id"] for r in rows if r["event"]=="violation"]
    if violations:
        label="positive"
    elif not missing and normal:
        label="negative"
    else:
        label="pending"
    return dict(label=label,coverage_basis="partial_sample" if missing else "exhaustive_finite_domain",
                declared=declared,normal_inputs=normal_inputs,missing=missing,normal_witnesses=normal,violations=violations)
