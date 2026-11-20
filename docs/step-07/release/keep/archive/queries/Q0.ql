import cpp
import shared
predicate gap(Expr e) { site(e) and none() }
from Expr e, string kind
where site(e) and (kind="site" or kind="alert" and not gap(e) and (pb508ca219667bd97fe40ae376636311ead7cde4cf53f0d4f718013e7ec1df88f(e) and p2b2f4876fa35b2486f5190d71f922f1f27844be0f245faf4209d9b195e28fe91(e) and pea79f1c2df1de6c77046dc24f75a35d0fc89cc835add45f1f9e77620d36524a6(e) and site(e) and not p2ad33a06805718b91f268af65028b94a72b3697d1fb5258dd0d3c15c5d803aaa(e)) or kind="gap" and gap(e))
select e.getFile().getBaseName() as filename, e.getLocation().getStartLine() as sl,
  e.getLocation().getStartColumn() as sc, e.getLocation().getEndLine() as el,
  e.getLocation().getEndColumn() as ec, kind,
  count(Expr other | site(other) and other.getLocation()=e.getLocation()) as multiplicity
