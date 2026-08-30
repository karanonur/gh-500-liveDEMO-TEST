/**
 * @name AST View - Attributes on Methods and Properties
 * @description Shows all attributes applied to PageModel methods and properties
 * @kind problem
 * @problem.severity recommendation
 * @id csharp/view-ast-attributes
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

from Attributable e, Attribute attr, PageModelClass pm
where 
  ((e instanceof Member and e.(Member).getDeclaringType() = pm) or e = pm) and
  attr = e.getAnAttribute()
select e, 
  "Element: " + e.toString() + 
  " | Attribute: " + attr.getType().getName() + 
  " | In class: " + pm.getName()
