"""Call a pinned toy program and decide on its integer access intent before memory is read."""
import ctypes as C
import hashlib
import json
from pathlib import Path

Permit = C.CFUNCTYPE(C.c_int, C.c_longlong, C.c_uint, C.c_uint, C.c_int)

def interval(offset,width,physical,logical,live=True):
    if type(logical) is not int or not 0 <= logical <= physical:
        raise ValueError("invalid object extent")
    end = offset + width
    event = ("no_access" if width==0 else "used" if live and offset>=0 and end<=logical else "violation")
    return dict(event=event,offset=offset,width=width,end=end,logical=logical,physical=physical,live_object=bool(live))


class Native:
    def __init__(self, folder):
        self.folder=Path(folder)
        self.registry=json.loads((self.folder/"registry.json").read_bytes())

    def observe(self,name,input_id,capacity):
        desc=self.registry[name]
        if type(input_id) is not int or input_id not in desc["inputs"]:
            raise ValueError("outside registered domain")
        lib=self.folder/(name+".so")
        if hashlib.sha256(lib.read_bytes()).hexdigest()!=desc["binary_sha256"]:
            raise ValueError("binary fingerprint mismatch")
        if type(capacity) is not int or capacity!=desc["contract"]["extent"]["value"]:
            raise ValueError("invalid approved capacity")
        run=C.CDLL(str(lib)).run
        run.argtypes=[C.c_int,Permit,C.POINTER(C.c_int)]
        seen=[]
        def inspect(offset,width,physical,live):
            row=interval(offset,width,physical,capacity,live)
            seen.append(row)
            return int(row["event"]=="used")
        counts=(C.c_int*3)()
        value=run(input_id,Permit(inspect),counts)
        if len(seen)>1:
            raise ValueError("unexpected repeated access")
        row=seen[0] if seen else {"event":"blocked"}
        if counts[0]!=int(row["event"]=="used"):
            raise ValueError("access-count mismatch")
        if name.startswith("oob") and seen:
            row.update(element_index=row["offset"]//4,index_type="unsigned int",index_unit="elements",
                       element_bytes=4,offset_unit="bytes",width_unit="bytes",offset_type="int64",
                       conversion="widen_unsigned_index_then_scale",negative_offset=row["offset"]<0)
        if row["event"]=="used":
            original=run(input_id,Permit(),(C.c_int*3)())
            if original!=value:
                raise ValueError("normal result mismatch")
            row["reference_value"]=original
        return dict(row,input_id=input_id,accesses=counts[0],value=value,
                    rebound=bool(counts[2]),rebindings=counts[2],initial_is_null=bool(counts[1]) if name.startswith("npd") else None,
                    generation="static-object@1" if row.get("live_object") else None)

    def edge(self,language,raw,width,narrow,capacity):
        if (language not in ("c","cpp") or capacity not in (8,255) or narrow not in (0,1)
                or type(raw) is not int or not -(1<<63)<=raw<1<<63 or type(width) is not int or not 0<=width<1<<32):
            raise ValueError("outside registered edge ABI")
        fn=getattr(C.CDLL(str(self.folder/("edge_"+language+".so"))),"edge"+str(capacity))
        fn.argtypes=[C.c_longlong,C.c_uint,C.c_int,Permit,C.POINTER(C.c_int)]
        seen=[]
        def inspect(offset,w,n,live):
            event=interval(offset,w,n,capacity,live)
            seen.append(event)
            return int(event["event"]=="used")
        counters=(C.c_int*2)()
        val=fn(raw,width,narrow,Permit(inspect),counters)
        row,=seen
        effects=lambda n:[int(x) for x in str(n)]
        row.update(raw=raw,conversion="uint8" if narrow else "int64",effects=effects(counters[0]),
                   accesses=counters[1],value=val)
        if row["event"]=="used":
            original=fn(raw,width,narrow,Permit(),counters)
            row["reference"]=dict(effects=effects(counters[0]),value=original)
        return row

    def signed_add(self,language,a,b):
        if language not in ("c","cpp") or any(type(i) is not int or not -(1<<31)<=i<1<<31 for i in (a,b)):
            raise ValueError("outside int32 ABI")
        fn=C.CDLL(str(self.folder/("edge_"+language+".so"))).checked_add
        fn.argtypes=[C.c_int,C.c_int,C.POINTER(C.c_int)]
        result=C.c_int()
        if not fn(a,b,C.byref(result)):
            return dict(completion="case_exec_failure",reason="undefined_signed_source_addition",operands=[a,b])
        return dict(completion="completed",effective=result.value,operands=[a,b])
