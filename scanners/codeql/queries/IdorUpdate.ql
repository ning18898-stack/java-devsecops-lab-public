/**
 * @name Lab article UPDATE lacks owner predicate
 * @description Experiment policy check for id/run-scoped MyBatis lab_articles UPDATE.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/lab-idor-update-owner
 * @tags security
 *       external/cwe/cwe-862
 */
import IdorPolicy
from Method method, Annotation annotation, string sql
where labUpdate(method, annotation, sql) and not ownerConstrained(sql)
select annotation, "Owner-only lab write policy requires a bound user_id predicate in the UPDATE WHERE clause."
