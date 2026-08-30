/**
 * @name Detailed AST View - Methods and Properties
 * @description Shows detailed AST structure of all PageModel methods and properties
 * @kind problem
 * @problem.severity recommendation
 * @id csharp/view-ast-detailed
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

from Member e, PageModelClass pm, string info
where 
  e.getDeclaringType() = pm and
  (
    (e instanceof Method and info = "Method: " + e.(Method).getName() + " | Returns: " + e.(Method).getReturnType().toString()) or
    (e instanceof Property and info = "Property: " + e.(Property).getName() + " | Type: " + e.(Property).getType().toString()) or
    (e instanceof Field and info = "Field: " + e.(Field).getName() + " | Type: " + e.(Field).getType().toString())
  )
select e, info + " | In class: " + pm.getName() + " | File: " + e.getFile().getBaseName()
