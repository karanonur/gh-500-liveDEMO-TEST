/**
 * @name Sensitive data exposure in logs
 * @description Detects potential logging of sensitive data such as passwords, tokens,
 *              or API keys, which could lead to information disclosure.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id csharp/aspnet/sensitive-data-logging
 * @tags security
 *       privacy
 *       logging
 *       external/cwe/cwe-532
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow

// Properties or parameters with sensitive names
class SensitiveData extends Expr {
  SensitiveData() {
    exists(Property prop |
      this = prop.getAnAccess() and
      prop.getName().regexpMatch("(?i).*(password|secret|token|apikey|api_key|privatekey|credential).*")
    ) or
    exists(Parameter param |
      this = param.getAnAccess() and
      param.getName().regexpMatch("(?i).*(password|secret|token|apikey|api_key|privatekey|credential).*")
    ) or
    exists(Variable var |
      this = var.getAnAccess() and
      var.getName().regexpMatch("(?i).*(password|secret|token|apikey|api_key|privatekey|credential).*")
    )
  }
}

// Logging method calls
class LoggingCall extends MethodCall {
  LoggingCall() {
    exists(Method m | m = this.getTarget() |
      m.getDeclaringType().getName().matches("ILogger%") and
      (m.getName().matches("Log%") or
       m.getName() = "LogInformation" or
       m.getName() = "LogWarning" or
       m.getName() = "LogError" or
       m.getName() = "LogDebug" or
       m.getName() = "LogTrace")
    )
  }
}

module SensitiveDataLoggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SensitiveData
  }

  predicate isSink(DataFlow::Node sink) {
    exists(LoggingCall call |
      sink.asExpr() = call.getAnArgument()
    )
  }
}

module SensitiveDataLoggingFlow = TaintTracking::Global<SensitiveDataLoggingConfig>;

from SensitiveDataLoggingFlow::PathNode source, SensitiveDataLoggingFlow::PathNode sink
where SensitiveDataLoggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "CRITICAL: Sensitive data from $@ may be exposed in application logs. " +
  "This could lead to credential leakage and unauthorized access.",
  source.getNode(), "sensitive property or variable"
