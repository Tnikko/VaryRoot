import cpp
import shared
from Expr e,string k,int v where site(e) and
(k="init" and v=initialIndex(e) or k="scale" and v=scale(e) or k="final" and v=finalIndex(e) or k="width" and v=width(e)
or k="threshold" and v=threshold(e) or k="taken" and taken(e) and v=1 or k="prop" and propagation(e) and v=1)
select e.getFile().getBaseName(),k,v