/**
 * @name Missing input validation in PageModel POST handlers
 * @description Detects POST action methods that accept BindProperty parameters but don't
 *              perform proper validation, which could lead to security vulnerabilities.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id csharp/aspnet/missing-input-validation
 * @tags security
 *       input-validation
 *       asp.net
 *       external/cwe/cwe-20
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

// Define POST action methods
class PostActionMethod extends Method {
  PostActionMethod() {
    this.getDeclaringType() instanceof PageModelClass and
    this.getName().regexpMatch("OnPost.*")
  }
}

// Find properties with BindProperty attribute
class BindPropertyField extends Property {
  BindPropertyField() {
    this.getDeclaringType() instanceof PageModelClass and
    exists(Attribute attr |
      attr = this.getAnAttribute() and
      attr.getType().hasName("BindPropertyAttribute")
    )
  }
}

predicate hasValidation(PostActionMethod method) {
  exists(PropertyAccess pa |
    pa.getEnclosingCallable() = method and
    pa.getProperty().hasName("IsValid") and
    pa.getQualifier().(PropertyAccess).getProperty().hasName("ModelState")
  )
  or
  exists(MethodCall mc, BindPropertyField prop |
    mc.getEnclosingCallable() = method and
    mc.getTarget().hasName("IsNullOrWhiteSpace") and
    prop.getDeclaringType() = method.getDeclaringType() and
    exists(PropertyAccess pa | 
      pa.getProperty() = prop and
      pa = mc.getAnArgument()
    )
  )
}

from PostActionMethod method, BindPropertyField prop
where
  prop.getDeclaringType() = method.getDeclaringType() and
  not hasValidation(method)
select method, "Security Warning: POST handler '" + method.getName() + 
       "' accepts user input via BindProperty '" + prop.getName() + 
       "' but doesn't validate it using ModelState.IsValid or string validation methods. " +
       "This could allow malicious input to be processed."
