# CodeQL AST Viewer Queries

These queries help you understand how CodeQL represents your C# code in its Abstract Syntax Tree (AST).

## Quick Reference

### 1. **view-ast.ql** - Basic AST View
- Shows raw AST elements for Contact.cshtml.cs
- **Output**: Graph visualization (in CodeQL extension)
- **Use**: Understanding overall structure

### 2. **view-ast-detailed.ql** - Methods & Properties
- Lists all methods, properties, and fields in PageModel classes
- Shows types and return values
- **Use**: Finding exact element names and types

### 3. **view-ast-method-calls.ql** - Method Call Analysis
- Shows every method call within PageModel methods
- **Use**: Debugging why logger usage detection isn't working

### 4. **view-ast-attributes.ql** - Attribute Inspector
- Lists all attributes on methods and properties
- **Use**: Checking for [BindProperty], [Authorize], etc.

## How to Use

### Step 1: Run an AST Query
```
Right-click on any view-ast-*.ql file → "CodeQL: Run Queries in Selected Files"
```

### Step 2: View Results
- Results appear in the "**CodeQL Query Results**" panel (bottom)
- Click any result to jump to the source code
- For `view-ast.ql`, you'll see a graph visualization

### Step 3: Debug Your Security Queries

If a security query returns no results, use AST viewers to check:

#### Example: Debugging "Missing Audit Logging" Query

1. **Run view-ast-method-calls.ql**
2. Look for `OnPostDelete` method
3. Check what method calls appear inside it
4. Verify if logger field access is detected

If you see logger calls but query still fails, check:
- Field name (is it `_logger` or something else?)
- Method name patterns (does `regexpMatch` cover your case?)
- Class hierarchy (is PageModel being detected?)

## Common Debugging Patterns

### Pattern 1: Find Why Logger Detection Fails

Run **view-ast-detailed.ql** and look for:
```
Field: _logger | Type: ILogger<ContactModel>
```

If you don't see the logger field, the class hierarchy might be wrong.

### Pattern 2: Find Why Method Isn't Detected

Check **view-ast-detailed.ql** for your method:
```
Method: OnPostDelete | Returns: IActionResult
```

If present but query fails, check your regex pattern:
```ql
this.getName().regexpMatch("OnPost(Delete|Remove|Destroy).*")
```

### Pattern 3: Check Attribute Detection

Run **view-ast-attributes.ql** to see:
```
Element: OnPostDelete | Attribute: ValidateAntiForgeryTokenAttribute
```

## Example Workflow

### Debugging security-missing-audit-logging.ql

1. **Run view-ast-detailed.ql**
   - Confirm: ContactModel class exists
   - Confirm: _logger field exists with ILogger type
   - Confirm: OnPostDelete method exists

2. **Run view-ast-method-calls.ql**
   - Check if logger calls appear in OnPostDelete
   - If yes: Query logic might be inverted
   - If no: Query should catch it (good!)

3. **Adjust your query** based on findings

## Tips

- **Start broad**: Use view-ast-detailed.ql to see everything
- **Then narrow**: Use specific queries for problem areas
- **Compare working vs broken**: Run AST viewer on Secure.cshtml.cs (which has logging) vs Contact.cshtml.cs (which doesn't)
- **Check types carefully**: `ILogger<T>` vs `ILogger` - the generic type matters!

## Advanced: Custom AST Queries

You can create custom AST viewers for specific scenarios:

```ql
// Find all FieldAccess expressions
from FieldAccess fa
where fa.getTarget().getName() = "_logger"
select fa, fa.getEnclosingCallable()
```

This helps you understand exactly how CodeQL sees field accesses in your code.

## Quick Test

Run this to verify AST viewer is working:

1. Open **view-ast-detailed.ql**
2. Right-click → Run Query
3. You should see results like:
   - `Method: OnGet | Returns: Void | In class: ContactModel`
   - `Method: OnPost | Returns: IActionResult | In class: ContactModel`
   - `Field: _logger | Type: ILogger | In class: ContactModel`

If you see these, AST viewer is working correctly!
