/**
 * @name Security Scan Suite for ASP.NET Core Applications
 * @description Comprehensive security scanning suite that runs multiple security checks
 *              to detect common vulnerabilities in ASP.NET Core web applications.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id csharp/aspnet/security-suite
 * @tags security
 *       asp.net
 *       audit
 */

import csharp

// ===== VULNERABILITY 1: Missing CSRF Protection =====
class PageModelClass extends Class {
  PageModelClass() {
    exists(Class baseClass |
      this.getABaseType+() = baseClass and
      baseClass.hasFullyQualifiedName("Microsoft.AspNetCore.Mvc.RazorPages", "PageModel")
    )
  }
}

class PostActionMethod extends Method {
  PostActionMethod() {
    this.getDeclaringType() instanceof PageModelClass and
    this.getName().regexpMatch("OnPost.*")
  }
}

predicate hasValidateAntiForgeryToken(Method m) {
  exists(Attribute attr |
    attr = m.getAnAttribute() and
    attr.getType().hasName("ValidateAntiForgeryTokenAttribute")
  ) or
  exists(Attribute attr |
    attr = m.getDeclaringType().getAnAttribute() and
    attr.getType().hasName("ValidateAntiForgeryTokenAttribute")
  )
}

predicate hasIgnoreAntiforgeryToken(Method m) {
  exists(Attribute attr |
    attr = m.getAnAttribute() and
    attr.getType().hasName("IgnoreAntiforgeryTokenAttribute")
  )
}

// ===== VULNERABILITY 2: Unsafe Deserialization =====
class DeserializationCall extends MethodCall {
  DeserializationCall() {
    (this.getTarget().hasName("Deserialize") or
     this.getTarget().hasName("DeserializeObject") or
     this.getTarget().hasName("FromXml")) and
    this.getEnclosingCallable().getDeclaringType() instanceof PageModelClass
  }
}

// ===== VULNERABILITY 3: Missing Authorization =====
class SensitiveActionMethod extends Method {
  SensitiveActionMethod() {
    this.getDeclaringType() instanceof PageModelClass and
    (this.getName().regexpMatch("OnPost(Delete|Remove|Update|Edit|Approve|Admin).*") or
     this.getName().regexpMatch("OnGet(Admin|Secure|Private).*"))
  }
}

predicate hasAuthorizationAttribute(Method m) {
  exists(Attribute attr |
    (attr = m.getAnAttribute() or attr = m.getDeclaringType().getAnAttribute()) and
    (attr.getType().hasName("AuthorizeAttribute") or
     attr.getType().getName().matches("%Authorize%"))
  )
}

// ===== Main Query Logic =====
from Element issue, string message, string severity
where
  // Check 1: CSRF Protection
  (exists(PostActionMethod method |
    issue = method and
    not hasValidateAntiForgeryToken(method) and
    not hasIgnoreAntiforgeryToken(method) and
    message = "SECURITY: POST handler '" + method.getName() + 
              "' may be vulnerable to CSRF attacks. Consider adding [ValidateAntiForgeryToken] attribute." and
    severity = "Medium"
  )) or
  
  // Check 2: Unsafe Deserialization  
  (exists(DeserializationCall call |
    issue = call and
    message = "SECURITY: Unsafe deserialization detected. Deserializing untrusted data can lead to " +
              "remote code execution vulnerabilities. Validate input and use safe deserialization methods." and
    severity = "High"
  )) or
  
  // Check 3: Missing Authorization
  (exists(SensitiveActionMethod method |
    issue = method and
    not hasAuthorizationAttribute(method) and
    message = "CRITICAL: Sensitive operation '" + method.getName() + 
              "' lacks [Authorize] attribute. This allows unauthenticated access to privileged functionality." and
    severity = "Critical"
  ))
  
select issue, severity + " - " + message
