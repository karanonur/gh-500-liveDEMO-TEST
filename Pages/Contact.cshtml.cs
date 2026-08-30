using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace _1202demoapp.Pages
{
    public class ContactModel : PageModel
    {
        private readonly ILogger<ContactModel> _logger;

        public ContactModel(ILogger<ContactModel> logger)
        {
            _logger = logger;
        }

        [BindProperty]
        public string Name { get; set; } = string.Empty;

        [BindProperty]
        public string Email { get; set; } = string.Empty;

        [BindProperty]
        public string Message { get; set; } = string.Empty;

        public bool SubmitSuccess { get; set; } = false;

        public void OnGet()
        {
            // SECURITY ISSUE: Not logging page access - CodeQL should detect this
            // No audit trail of who viewed the contact form
        }

        public IActionResult OnPost()
        {
            // SECURITY ISSUE: Processing user input without any logging
            // This makes it impossible to audit who submitted what data
            // No way to track potential abuse or investigate incidents
            
            if (string.IsNullOrWhiteSpace(Name) || string.IsNullOrWhiteSpace(Email))
            {
                return Page();
            }

            // Processing form without audit trail
            SubmitSuccess = true;
            return Page();
        }

        public IActionResult OnPostDelete(int id)
        {
            // CRITICAL SECURITY ISSUE: Deleting data without logging
            // No audit trail for destructive operations
            // Impossible to investigate unauthorized deletions
            return RedirectToPage();
        }
        
        public IActionResult OnPostApprove(int id)
        {
            // Another method without logging
            return RedirectToPage();
        }
    }
}
