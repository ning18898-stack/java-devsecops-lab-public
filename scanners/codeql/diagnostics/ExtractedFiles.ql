import java
from CompilationUnit unit
where unit.fromSource()
select unit.getFile().getRelativePath()
