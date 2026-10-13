/**
 * @name Request input in MyBatis provider SQL
 * @description Tracks request parameters into annotation-selected provider SQL text.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id java/lab-mybatis-provider-sqli
 * @tags security
 *       external/cwe/cwe-089
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import MyBatisProvider

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { requestParameter(node) }
  predicate isSink(DataFlow::Node node) { providerSqlReturn(node) }
  predicate isAdditionalFlowStep(DataFlow::Node input, DataFlow::Node output) {
    providerArgumentStep(input, output)
  }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Request input reaches provider SQL text through the annotated MyBatis parameter map."
