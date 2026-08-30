/**
 * @name PageModel action methods without logging
 * @description Finds PageModel action methods (OnGet, OnPost, etc.) that don't use their ILogger field,
 *              which may make debugging and monitoring more difficult.
 * @kind problem
 * @problem.severity warning
 * @id csharp/aspnet/pagemodel-missing-logging
 * @tags maintainability
 *       logging
 *       asp.net
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

// Define PageModel action methods (OnGet, OnPost, OnPut, OnDelete, etc.)
class PageModelActionMethod extends Method {
  PageModelActionMethod() {
    this.getDeclaringType() instanceof PageModelClass and
    this.getName().regexpMatch("On(Get|Post|Put|Delete|Patch).*")
  }
}

// Find ILogger fields in PageModel classes
class LoggerField extends Field {
  LoggerField() {
    this.getDeclaringType() instanceof PageModelClass and
    this.getType().getName().matches("ILogger%")
  }
}

from PageModelActionMethod method, LoggerField logger
where
  logger.getDeclaringType() = method.getDeclaringType() and
  not exists(FieldAccess fa | 
    fa.getTarget() = logger and 
    fa.getEnclosingCallable() = method
  )
select method, "This PageModel action method has access to logger field '" + logger.getName() + "' but doesn't use it for logging."