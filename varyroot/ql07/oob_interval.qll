import cpp
import semmle.code.cpp.controlflow.ControlFlowGraph
import contract

// This module contains only shared interval and CFG relations. The generated
// contract supplies API, target, field paths, argument positions and width.
predicate targetCopy(FunctionCall copy, Variable source, Variable root) {
  copy.getTarget().hasName(copyApiName()) and
  copy.getEnclosingFunction().hasName(targetFunctionName()) and
  copy.getLocation().getStartLine() = targetLine() and
  copy.getArgument(destinationArgument()).(VariableAccess).getTarget().hasName(destinationName()) and
  copy.getArgument(sourceArgument()).(VariableAccess).getTarget() = source and
  payloadField(source.getInitializer().getExpr(), root) and
  copy.getArgument(widthArgument()).getValue().toInt() = copyWidthBytes()
}

predicate logicalEnd(Variable end, Variable source, Variable root) {
  exists(PointerAddExpr addition |
    addition = end.getInitializer().getExpr() and
    addition.getLeftOperand().(VariableAccess).getTarget() = source and
    logicalLengthField(addition.getRightOperand(), root) and
    addition.getEnclosingFunction() = source.getInitializer().getExpr().getEnclosingFunction()
  )
}

predicate site(FunctionCall copy) {
  exists(Variable source, Variable root, Variable end |
    targetCopy(copy, source, root) and logicalEnd(end, source, root)
  )
}

// Reachability uses basic blocks and node order within one block. It is
// restricted to the selected function and call, never a global node closure.
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
        or fromBlock.getASuccessor+() = fromBlock
      )
    )
  )
}

predicate guardControls(IfStmt guard, FunctionCall copy) {
  guard.getEnclosingFunction() = copy.getEnclosingFunction() and
  copy.getEnclosingStmt().getParentStmt*() = guard.getThen() and
  reaches(guard.getCondition(), copy)
}

predicate totalGuard(FunctionCall copy, Variable root) {
  exists(IfStmt guard, GEExpr test |
    guardControls(guard, copy) and guard.getCondition() = test and
    totalLengthField(test.getLeftOperand(), root) and
    test.getRightOperand().getValue().toInt() = copyWidthBytes()
  )
}

predicate remainingGuard(FunctionCall copy, Variable source, Variable root) {
  exists(IfStmt guard, GEExpr test, PointerDiffExpr difference, Variable end |
    guardControls(guard, copy) and guard.getCondition() = test and
    test.getLeftOperand() = difference and
    difference.getLeftOperand().(VariableAccess).getTarget() = end and
    difference.getRightOperand().(VariableAccess).getTarget() = source and
    logicalEnd(end, source, root) and
    test.getRightOperand().getValue().toInt() = copyWidthBytes()
  )
}

predicate positivePointerAdvance(FunctionCall copy, Variable source) {
  exists(AssignPointerAddExpr advance |
    advance.getEnclosingFunction() = copy.getEnclosingFunction() and
    advance.getLValue().(VariableAccess).getTarget() = source and
    advance.getRValue().getValue().toInt() > 0 and
    reaches(advance, copy)
  )
}

predicate guardCovered(FunctionCall copy) {
  exists(Variable source, Variable root |
    targetCopy(copy, source, root) and
    (totalGuard(copy, root) or remainingGuard(copy, source, root))
  )
}

// The S0 lane treats a total-length guard as sufficient. A direct remaining
// guard is stronger and also quiet. Unrecognized guard forms are not scored.
predicate baselineAlert(FunctionCall copy) {
  exists(Variable source, Variable root |
    targetCopy(copy, source, root) and
    positivePointerAdvance(copy, source) and
    not totalGuard(copy, root) and not remainingGuard(copy, source, root) and
    not exists(IfStmt guard, GEExpr test |
      guardControls(guard, copy) and guard.getCondition() = test
    )
  )
}

// The candidate S* lane flags the proven mismatch shape: a total-length guard
// reaches a copy after a positive source advance and no remaining guard protects it.
predicate revisedAlert(FunctionCall copy) {
  exists(Variable source, Variable root |
    targetCopy(copy, source, root) and
    positivePointerAdvance(copy, source) and
    totalGuard(copy, root) and
    not remainingGuard(copy, source, root)
  )
}
