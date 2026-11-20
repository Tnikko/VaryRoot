import cpp
import shared
predicate gap(Expr e) { site(e) and none() }
from Expr e, string kind
where site(e) and (kind="site" or kind="alert" and not gap(e) and (p91880d030f9342cda0978815e9516afa42a2e16afea97eda41daaf62be6f06b6(e) and p03e3c825593e48c2eebb31466803104c2dcf308e82ebb185b5df9593851eab70(e) and p3a8c3fe37ab3ef86ca2e4c267ac7d10342e46e3bfb45f3adfb997746997c7711(e) and site(e) and not p5bdf7f3c742a9a8ee873d818adfbe722ea9190f788078ea7e186a391bfca518a(e)) or kind="gap" and gap(e))
select e.getFile().getBaseName() as filename, e.getLocation().getStartLine() as sl,
  e.getLocation().getStartColumn() as sc, e.getLocation().getEndLine() as el,
  e.getLocation().getEndColumn() as ec, kind,
  count(Expr other | site(other) and other.getLocation()=e.getLocation()) as multiplicity
