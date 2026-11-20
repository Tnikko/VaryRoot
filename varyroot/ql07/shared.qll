import cpp

// The compiler admits only the registered single-function source shapes.
predicate npd(Expr e) { e.(FunctionCall).getTarget().hasName("read_required") }
predicate spanRead(Expr e) { e.(FunctionCall).getTarget().hasName("read_span") }
predicate indexed(Expr e) { e.(ArrayExpr).getArrayBase().(VariableAccess).getTarget().hasName("data") }
predicate site(Expr e) {
  e.getEnclosingFunction().hasName("sample") and (npd(e) or indexed(e) or spanRead(e))
}

IfStmt localTest(Expr e) { result.getEnclosingFunction() = e.getEnclosingFunction() and result.getFile() = e.getFile() }
predicate exits(Expr e) { localTest(e).getThen() instanceof ReturnStmt }
predicate assigned(Expr e) { localTest(e).getThen().(ExprStmt).getExpr() instanceof AssignExpr }
Variable indexVar(Expr e) {
  result = e.(ArrayExpr).getArrayOffset().(VariableAccess).getTarget() or
  result = e.(FunctionCall).getArgument(1).(VariableAccess).getTarget()
}
int initialIndex(Expr e) { result = indexVar(e).getInitializer().getExpr().getValue().toInt() }
int threshold(Expr e) { result = localTest(e).getCondition().(BinaryOperation).getRightOperand().getValue().toInt() }
predicate taken(Expr e) { initialIndex(e) >= threshold(e) }
int finalIndex(Expr e) {
  if taken(e) and assigned(e)
  then result = localTest(e).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().getValue().toInt()
  else result = initialIndex(e)
}
int scale(Expr e) {
  result = e.(ArrayExpr).getType().getSize() or
  result = e.(FunctionCall).getArgument(0).getType().(ArrayType).getBaseType().getSize()
}
int width(Expr e) {
  indexed(e) and result = e.getType().getSize() or
  spanRead(e) and result = e.(FunctionCall).getArgument(2).getValue().toInt()
}
predicate bodyMissing(Expr e) { spanRead(e) and not exists(e.(FunctionCall).getTarget().getBlock()) }
predicate isExit(Expr e) { exits(e) and (npd(e) or taken(e)) }
predicate rebound(Expr e) { npd(e) and assigned(e) }
predicate origin(Expr e) {
  site(e) and (npd(e) and exists(e.(FunctionCall).getArgument(0).(VariableAccess).getTarget().getInitializer())
    or exists(initialIndex(e)))
}
predicate propagation(Expr e) { site(e) and not isExit(e) }
