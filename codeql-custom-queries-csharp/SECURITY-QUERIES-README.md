# CodeQL Security Scanning Queries for ASP.NET Core

This repository contains custom CodeQL security queries designed to detect common vulnerabilities in ASP.NET Core web applications.

## Security Queries

### 1. **Missing Audit Logging for Destructive Operations** (`security-missing-audit-logging.ql`)
- **Severity**: Error (7.5/10)
- **CWE**: CWE-778 (Insufficient Logging)
- **Description**: Detects PageModel action methods that perform destructive operations (Delete, Remove, etc.) without proper audit logging
- **Impact**: Prevents investigation of unauthorized or accidental data loss
- **Example**: `OnPostDelete()` methods without `_logger.LogInformation()` calls

### 2. **Missing Input Validation** (`security-missing-input-validation.ql`)
- **Severity**: Warning (6.0/10)
- **CWE**: CWE-20 (Improper Input Validation)
- **Description**: Detects POST handlers that accept user input via `[BindProperty]` but don't validate it
- **Impact**: Allows malicious input to be processed without validation
- **Example**: POST handlers without `ModelState.IsValid` checks

### 3. **SQL Injection Risk** (`security-sql-injection-risk.ql`)
- **Severity**: Error (9.0/10)
- **CWE**: CWE-89 (SQL Injection)
- **Description**: Path-problem query that tracks user input flowing to SQL execution without parameterization
- **Impact**: Critical vulnerability allowing database compromise
- **Example**: User input concatenated directly into SQL queries

### 4. **Cross-Site Scripting (XSS) Vulnerability** (`security-xss-vulnerability.ql`)
- **Severity**: Error (8.5/10)
- **CWE**: CWE-79 (Cross-Site Scripting)
- **Description**: Path-problem query tracking user input to HTML output without encoding
- **Impact**: Allows attackers to inject malicious scripts
- **Example**: User input passed to `Html.Raw()` or ViewData without sanitization

### 5. **Insecure Configuration** (`security-insecure-configuration.ql`)
- **Severity**: Warning (7.0/10)
- **CWE**: CWE-16 (Configuration)
- **Description**: Detects security misconfigurations in application setup
- **Impact**: May allow unauthorized access due to missing authentication/authorization
- **Example**: Using `UseAuthorization()` without `UseAuthentication()`

### 6. **Sensitive Data Exposure in Logs** (`security-sensitive-data-logging.ql`)
- **Severity**: Error (8.0/10)
- **CWE**: CWE-532 (Information Exposure Through Log Files)
- **Description**: Path-problem query detecting passwords, tokens, or keys in log statements
- **Impact**: Credential leakage leading to unauthorized access
- **Example**: Logging variables named "password", "apiKey", "token", etc.

### 7. **Comprehensive Security Suite** (`security-comprehensive-suite.ql`)
- **Severity**: Error (8.0/10)
- **Description**: All-in-one query checking for:
  - Missing CSRF protection (`[ValidateAntiForgeryToken]`)
  - Unsafe deserialization of untrusted data
  - Missing authorization on sensitive operations
- **Impact**: Multiple security vulnerabilities in a single scan

## Usage

### Creating a CodeQL Database

First, create a CodeQL database from your application:

```powershell
# Navigate to your project directory
cd C:\1202demoapp

# Create the database
codeql database create codeqldb --language=csharp --command="dotnet build"
```

### Running Individual Queries

Run a specific security query against your database:

```powershell
# Run the audit logging query
codeql query run codeql-custom-queries-csharp/security-missing-audit-logging.ql --database=codeqldb

# Run the SQL injection query
codeql query run codeql-custom-queries-csharp/security-sql-injection-risk.ql --database=codeqldb

# Run the comprehensive suite
codeql query run codeql-custom-queries-csharp/security-comprehensive-suite.ql --database=codeqldb
```

### Running All Security Queries

Run all queries in the directory:

```powershell
# Run all queries and generate SARIF output
codeql database analyze codeqldb codeql-custom-queries-csharp --format=sarif-latest --output=security-results.sarif

# Generate readable results
codeql database analyze codeqldb codeql-custom-queries-csharp --format=text
```

### Viewing Results in VS Code

1. Install the CodeQL extension for VS Code
2. Open the SARIF file: `security-results.sarif`
3. Results will appear in the Problems panel with clickable links to source code

## Detected Vulnerabilities in Sample App

Based on the current application code, these queries will detect:

### In `Contact.cshtml.cs`:
- ✅ **OnPost()** - Missing audit logging (Warning)
- ✅ **OnPostDelete()** - Missing audit logging for destructive operation (Critical)
- ✅ **OnPostApprove()** - Missing audit logging (Warning)
- ✅ **OnPostDelete()** - Missing authorization check (Critical)

### In `Program.cs`:
- ⚠️ **Configuration** - Authorization without Authentication (if applicable)

### In `Secure.cshtml.cs`:
- ✅ **OnPost()** - Properly implements logging (Good practice example)

## Customization

You can customize these queries by:
1. Adjusting severity levels in the query metadata
2. Modifying regex patterns for method name matching
3. Adding additional security checks to the comprehensive suite
4. Creating custom taint-tracking configurations

## Integration with CI/CD

Add to your pipeline (GitHub Actions example):

```yaml
- name: Run CodeQL Security Scan
  run: |
    codeql database create codeqldb --language=csharp --command="dotnet build"
    codeql database analyze codeqldb codeql-custom-queries-csharp --format=sarif-latest --output=results.sarif
    
- name: Upload Security Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## References

- [CodeQL for C#](https://codeql.github.com/docs/codeql-language-guides/codeql-for-csharp/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [ASP.NET Core Security Best Practices](https://learn.microsoft.com/aspnet/core/security/)

## License

These queries are provided as-is for security testing purposes.
