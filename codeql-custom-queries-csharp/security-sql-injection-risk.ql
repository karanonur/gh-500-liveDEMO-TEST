/**
 * @name Potential SQL injection vulnerability
 * @description Detects potential SQL injection vulnerabilities where user input
 *              might be concatenated directly into SQL queries without parameterization.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id csharp/aspnet/sql-injection-risk
 * @tags security
 *       sql-injection
 *       external/cwe/cwe-89
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking

// Properties that can be bound from user input
class UserInputProperty extends Property {
  UserInputProperty() {
    exists(Attribute attr |
      attr = this.getAnAttribute() and
      attr.getType().hasName("BindPropertyAttribute")
    )
  }
}

// SQL execution methods
class SqlExecutionCall extends MethodCall {
  SqlExecutionCall() {
    this.getTarget().getName().regexpMatch(".*(ExecuteSql|ExecuteRaw|Query|Command).*") or
    this.getTarget().getDeclaringType().getName().matches("%Command") or
    this.getTarget().getDeclaringType().getName().matches("%Connection")
  }
}

module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;

import SqlInjectionFlow::PathGraph

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(UserInputProperty prop |
      source.asExpr() = prop.getAnAccess()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(SqlExecutionCall call |
      sink.asExpr() = call.getAnArgument()
    )
  }
}

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "CRITICAL: Potential SQL injection vulnerability. User input from $@ flows to SQL execution without proper parameterization.",
  source.getNode(), "user input property"
