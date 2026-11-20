"""Exercise production C on isolated copies of approved, immutable B ledgers."""
import argparse
import shutil
import sqlite3
from pathlib import Path

from varyroot.c_pipeline import submit
from varyroot.ledger import Ledger
from tools.codeql07.runner import save


def copy_ledger(source,target):
    target.mkdir(parents=True)
    with sqlite3.connect((source/"ledger.sqlite3").resolve().as_uri()+"?mode=ro",uri=True) as src:
        with sqlite3.connect(target/"ledger.sqlite3") as dest:
            src.backup(dest)
    for folder in ("b-objects","published-objects","seed-objects"):
        if (source/folder).exists():
            shutil.copytree(source/folder,target/folder)
    return Ledger(target)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for arg in ("source","run","out","tools","image"):
        parser.add_argument(arg)
    parser.add_argument("--reuse")
    parser.add_argument("--repair-from")
    parser.add_argument("--profile",default="registered")
    args=parser.parse_args()
    out=Path(args.out)
    db=copy_ledger(Path(args.source),out/"store")
    result=submit(db,args.run,out/"c",Path(args.tools),args.image,profile=args.profile,
                  reuse=args.reuse,repair_from=args.repair_from)
    print(args.run,result["state"],result.get("freeze_id",""))
