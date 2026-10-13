/** Narrow model for annotation-selected static providers with @Param keys.
 * MyBatis ParamNameResolver builds a map; ProviderSqlSource invokes the selected
 * provider with that map. No arbitrary mapper-to-provider edge is permitted.
 */
import java
import semmle.code.java.dataflow.DataFlow

predicate selectedProvider(Method mapper, Method provider) {
  exists(Annotation a |
    a = mapper.getAnAnnotation() and
    a.getType().hasQualifiedName("org.apache.ibatis.annotations", "SelectProvider") and
    provider.getDeclaringType() = a.getTypeValue("type") and
    provider.getName() = a.getStringValue("method") and
    provider.isStatic() and provider.getNumberOfParameters() = 1 and
    provider.getParameter(0).getType().getErasure().(RefType).hasQualifiedName("java.util", "Map")
  )
}

predicate providerArgumentStep(DataFlow::Node input, DataFlow::Node output) {
  exists(MethodCall call, Method provider, int index, Annotation param, MethodCall lookup |
    selectedProvider(call.getMethod(), provider) and
    param = call.getMethod().getParameter(index).getAnAnnotation() and
    param.getType().hasQualifiedName("org.apache.ibatis.annotations", "Param") and
    lookup.getEnclosingCallable() = provider and lookup.getMethod().getName() = "get" and
    lookup.getQualifier().(VarAccess).getVariable() = provider.getParameter(0) and
    lookup.getArgument(0).(StringLiteral).getValue() = param.getStringValue("value") and
    input.asExpr() = call.getArgument(index) and output.asExpr() = lookup
  )
}

predicate providerSqlReturn(DataFlow::Node node) {
  exists(Method mapper, Method provider, ReturnStmt ret |
    selectedProvider(mapper, provider) and ret.getEnclosingCallable() = provider and
    node.asExpr() = ret.getResult()
  )
}

predicate requestParameter(DataFlow::Node node) {
  exists(Parameter p, Annotation a |
    node.asParameter() = p and a = p.getAnAnnotation() and
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam")
  )
}
