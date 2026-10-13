/**
 * @name Lab write lacks recognized owner authorization
 * @description Checks the experiment's fail-closed owner inequality and trusted identity passed to UPDATE.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id java/lab-idor-service-owner
 * @tags security
 *       external/cwe/cwe-862
 */
import IdorPolicy
from MethodCall write, Annotation annotation, string sql
where labUpdate(write.getMethod(), annotation, sql) and not ownerGuard(write)
select write, "Lab write lacks the recognized controlling owner guard and principal identity argument; inspect authorization."
