/**
 * @name Provider flow without custom framework bridge
 * @kind problem
 * @problem.severity warning
 * @id java/lab-provider-without-bridge
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import queries.MyBatisProvider
module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { requestParameter(n) }
  predicate isSink(DataFlow::Node n) { providerSqlReturn(n) }
}
module Flow = TaintTracking::Global<Config>;
from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "Request reaches SQL without the custom bridge."
