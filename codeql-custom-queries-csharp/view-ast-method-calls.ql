/**
 * @name AST View - Method Calls and Logger Usage
 * @description Shows all method calls within PageModel methods, useful for debugging logging queries
 * @kind problem
 * @problem.severity recommendation
 * @id csharp/view-ast-method-calls
 */

import csharp

class PageModelClass extends Class {
  PageModelClass() {
    exists(Class baseClass |
      this.getABaseType+() = baseClass and
      baseClass.hasFullyQualifiedName("Microsoft.AspNetCore.Mvc.RazorPages", "PageModel")
    )
  }
}

from MethodCall call, Method enclosing, PageModelClass pm
where 
  enclosing.getDeclaringType() = pm and
  call.getEnclosingCallable() = enclosing
select call, 
  "In method: " + enclosing.getName() + 
  " | Calling: " + call.getTarget().getName() + 
  " | On type: " + call.getTarget().getDeclaringType().getName() + 
  " | Class: " + pm.getName()
