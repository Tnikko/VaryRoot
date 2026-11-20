import cpp
import semmle.code.cpp.controlflow.ControlFlowGraph
import contract

// API names, argument positions and the success value are supplied by contract.qll.
predicate outputDefinition(FunctionCall call, Variable value) {
  call.getTarget().hasName(apiName()) and
  (
    call.getArgument(outputArgument()).(AddressOfExpr).getAddressable() = value
    or
    aliasMode() = "initializer_address_of" and
    exists(VariableAccess alias |
      alias = call.getArgument(outputArgument()) and
      alias.getTarget().getInitializer().getExpr().(AddressOfExpr).getAddressable() = value
    )
  )
}

Variable sinkBase(Expr site) {
  site.(FieldAccess).getTarget().hasName(sinkMember()) and
  result = site.(FieldAccess).getQualifier().(ArrayExpr)
                    .getArrayBase().(VariableAccess).getTarget()
}

predicate successLoop(FunctionCall call, Expr access) {
  exists(ForStmt loop, BinaryOperation test, Variable status, AssignExpr assignment |
    (loop.getCondition() = test or
     loop.getCondition().(LogicalAndExpr).getLeftOperand() = test) and
    test.getLeftOperand().(VariableAccess).getTarget() = status and
    test.getRightOperand().getValue().toInt() = successNumber() and
    assignment.getLValue().(VariableAccess).getTarget() = status and
    assignment.getRValue() = call and
    assignment.getEnclosingStmt() = loop and
    access.getEnclosingFunction() = loop.getEnclosingFunction() and
    test.getASuccessor+() = access
  )
}

predicate site(Expr access) {
  exists(Variable value, FunctionCall call |
    value = sinkBase(access) and
    outputDefinition(call, value) and
    call.getEnclosingFunction() = access.getEnclosingFunction() and
    successLoop(call, access) and
    noExplicitReassignment(call, value) and
    reaches(call, access)
  )
}

predicate nullCheck(IfStmt statement, Variable value) {
  exists(EQExpr test |
    statement.getCondition() = test and
    (
      test.getLeftOperand().(VariableAccess).getTarget() = value and
      test.getRightOperand().getValue().toInt() = 0
      or
      test.getRightOperand().(VariableAccess).getTarget() = value and
      test.getLeftOperand().getValue().toInt() = 0
    )
  )
  or
  statement.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget() = value
}

predicate checkSeen(Expr access) {
  loopDirect(access)
  or
  exists(Variable value, IfStmt statement, FunctionCall call |
    value = sinkBase(access) and
    outputDefinition(call, value) and
    nullCheck(statement, value) and
    reaches(call, statement.getCondition()) and
    reaches(statement.getCondition(), access)
  )
}

// Repeated calls to the declared API can update the same slot on loop iterations.
// An explicit assignment makes the binding inapplicable to this family.
predicate noExplicitReassignment(FunctionCall call, Variable value) {
  not exists(VariableAccess changed |
    changed.getEnclosingFunction() = call.getEnclosingFunction() and
    changed.getTarget() = value and changed.isModified()
  )
}

pragma[noinline]
predicate reaches(ControlFlowNode source, ControlFlowNode target) {
  source = target
  or
  exists(BasicBlock fromBlock, BasicBlock toBlock |
    fromBlock = source.getBasicBlock() and
    toBlock = target.getBasicBlock() and
    (
      fromBlock != toBlock and fromBlock.getASuccessor+() = toBlock
      or
      fromBlock = toBlock and
      (
        exists(int sourceIndex, int targetIndex |
          fromBlock.getNode(sourceIndex) = source and
          fromBlock.getNode(targetIndex) = target and
          sourceIndex <= targetIndex
        )
        or
        fromBlock.getASuccessor+() = fromBlock
      )
    )
  )
}

predicate blocked(Expr access) {
  loopDirect(access)
  or
  exists(Variable value, IfStmt statement, ControlFlowNode trueBranch,
         FunctionCall call |
    value = sinkBase(access) and
    outputDefinition(call, value) and
    nullCheck(statement, value) and
    reaches(call, statement.getCondition()) and
    reaches(statement.getCondition(), access) and
    trueBranch = statement.getCondition().getATrueSuccessor() and
    (
      statement.getThen() instanceof ReturnStmt or
      statement.getThen() instanceof BreakStmt or
      statement.getThen() instanceof GotoStmt and not reaches(trueBranch, access)
    )
  )
}

predicate loopDirect(Expr access) {
  exists(ForStmt loop, LogicalAndExpr condition, Variable value,
         FunctionCall call |
    value = sinkBase(access) and
    loop.getCondition() = condition and
    condition.getRightOperand().(VariableAccess).getTarget() = value and
    outputDefinition(call, value) and
    // A false condition exits this loop evaluation. Later outer-loop iterations
    // may call the API again, so unrestricted CFG reachability is too broad here.
    access.getEnclosingStmt().getParentStmt*() = loop.getStmt() and
    reaches(call, condition.getRightOperand()) and
    reaches(condition.getRightOperand(), access) and
    reaches(condition.getRightOperand().getATrueSuccessor(), access)
  )
}
