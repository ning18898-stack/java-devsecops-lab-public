import java
import semmle.code.java.dataflow.DataFlow
import queries.MyBatisProvider
from DataFlow::Node input, DataFlow::Node output
where providerArgumentStep(input, output)
select input, output, "Annotation-selected @Param key to provider Map.get model edge"
