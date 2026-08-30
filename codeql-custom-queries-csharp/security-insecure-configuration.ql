/**
 * @name Insecure application configuration
 * @description Detects potential security misconfigurations in ASP.NET Core applications,
 *              such as missing authentication/authorization middleware.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id csharp/aspnet/insecure-configuration
 * @tags security
 *       configuration
 *       asp.net
 *       external/cwe/cwe-16
 */

import csharp

// Find the main Program.cs or Startup.cs configuration
class WebApplicationBuilder extends Class {
  WebApplicationBuilder() {
    this.hasFullyQualifiedName("Microsoft.AspNetCore.Builder", "WebApplication") or
    this.hasFullyQualifiedName("Microsoft.AspNetCore.Builder", "WebApplicationBuilder")
  }
}

// Methods that configure the application pipeline
class ConfigurationMethod extends Method {
  ConfigurationMethod() {
    (this.getName() = "Main" or this.getName() = "Configure") and
    exists(MethodCall call |
      call.getEnclosingCallable() = this and
      call.getTarget().getDeclaringType() instanceof WebApplicationBuilder
    )
  }
}

// Check if authentication is configured
predicate hasAuthentication(ConfigurationMethod method) {
  exists(MethodCall call |
    call.getEnclosingCallable() = method and
    (call.getTarget().getName() = "UseAuthentication" or
     call.getTarget().getName() = "AddAuthentication")
  )
}

// Check if authorization is configured
predicate hasAuthorization(ConfigurationMethod method) {
  exists(MethodCall call |
    call.getEnclosingCallable() = method and
    (call.getTarget().getName() = "UseAuthorization" or
     call.getTarget().getName() = "AddAuthorization")
  )
}

// Check if HTTPS redirection is configured
predicate hasHttpsRedirection(ConfigurationMethod method) {
  exists(MethodCall call |
    call.getEnclosingCallable() = method and
    call.getTarget().getName() = "UseHttpsRedirection"
  )
}

from ConfigurationMethod method
where
  // Has authorization but no authentication (common misconfiguration)
  (hasAuthorization(method) and not hasAuthentication(method))
select method, "Security Warning: Application uses Authorization middleware but doesn't configure " +
       "Authentication middleware. This may allow unauthorized access. Add app.UseAuthentication() " +
       "before app.UseAuthorization()."
