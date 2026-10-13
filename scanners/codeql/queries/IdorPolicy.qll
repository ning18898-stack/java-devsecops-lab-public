import java
import semmle.code.java.controlflow.Guards

predicate labUpdate(Method method, Annotation annotation, string sql) {
  annotation = method.getAnAnnotation() and
  annotation.getType().hasQualifiedName("org.apache.ibatis.annotations", "Update") and
  sql = annotation.getAStringArrayValue("value").toLowerCase() and
  sql.regexpMatch("(?s)\\s*update\\s+lab_articles\\s+set\\b.*\\bwhere\\b.*") and
  sql.regexpMatch("(?s).*\\bwhere\\b.*\\bid\\s*=\\s*#\\{[^}]+\\}.*") and
  sql.regexpMatch("(?s).*\\bwhere\\b.*\\brun_id\\s*=\\s*#\\{[^}]+\\}.*")
}

bindingset[sql]
predicate ownerConstrained(string sql) {
  sql.regexpMatch("(?s).*\\bwhere\\b.*\\buser_id\\s*=\\s*#\\{[^}]+\\}.*")
}

/** Recognizes the lab's fail-closed inequality guard controlling the write.
 * Accessor names are the documented policy contract, not class/file names.
 */
predicate ownerGuard(MethodCall write) {
  exists(NEExpr comparison, MethodCall owner, MethodCall actor, IfStmt branch, ThrowStmt refusal |
    comparison.getLeftOperand() = owner and owner.getMethod().getName() = "userId" and
    comparison.getRightOperand() = actor and actor.getMethod().getName() = "getId" and
    branch.getCondition() = comparison and refusal = branch.getThen().getAChild*() and
    comparison.(Guard).controls(write.getControlFlowNode().getBasicBlock(), false) and
    exists(MethodCall passed |
      passed = write.getAnArgument() and passed.getMethod().getName() = "getId" and
      passed.getQualifier().(VarAccess).getVariable() = actor.getQualifier().(VarAccess).getVariable()
    )
  )
}
