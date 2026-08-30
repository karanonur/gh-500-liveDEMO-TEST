/**
 * @name Missing audit logging for destructive operations
 * @description Detects PageModel action methods that perform destructive operations
 *              (Delete, Remove, etc.) without using logging, which creates security risks
 *              and prevents proper audit trails.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id csharp/aspnet/missing-destructive-operation-audit
 * @tags security
 *       audit
 *       logging
 *       asp.net
 *       external/cwe/cwe-778
 */

import csharp

// Define a class that represents ASP.NET PageModel classes
class PageModelClass extends Class {
  PageModelClass() {
    exists(Class baseClass |
      this.getABaseType+() = baseClass and
      baseClass.hasFullyQualifiedName("Microsoft.AspNetCore.Mvc.RazorPages", "PageModel")
    )
  }
}

// Define destructive PageModel action methods (OnPostDelete, OnPostRemove, etc.)
class DestructiveActionMethod extends Method {
  DestructiveActionMethod() {
    this.getDeclaringType() instanceof PageModelClass and
    this.getName().regexpMatch("OnPost(Delete|Remove|Destroy|Purge|Drop).*")
  }
}

// Find ILogger fields in PageModel classes
class LoggerField extends Field {
  LoggerField() {
    this.getDeclaringType() instanceof PageModelClass and
    this.getType().getName().matches("ILogger%")
  }
}

from DestructiveActionMethod method, LoggerField logger
where
  logger.getDeclaringType() = method.getDeclaringType() and
  not exists(FieldAccess fa | 
    fa.getTarget() = logger and 
    fa.getEnclosingCallable() = method
  )
select method, "CRITICAL SECURITY ISSUE: Destructive operation '" + method.getName() + 
       "' lacks audit logging. This creates a security risk as there is no audit trail " +
       "for data deletion, making it impossible to investigate unauthorized or accidental data loss."
