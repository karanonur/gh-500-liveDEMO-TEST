using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace _1202demoapp.Pages
{
    public class SecureModel : PageModel
    {
        private readonly ILogger<SecureModel> _logger;

        public SecureModel(ILogger<SecureModel> logger)
        {
            _logger = logger;
        }

        [BindProperty]
        public string UserName { get; set; } = string.Empty;

        [BindProperty]
        public string Data { get; set; } = string.Empty;

        public bool Success { get; set; } = false;

        public void OnGet()
        {
            // GOOD PRACTICE: Logging page access
            _logger.LogInformation("Secure form page accessed at {Time}", DateTime.UtcNow);
        }

        public IActionResult OnPost()
        {
            // GOOD PRACTICE: Logging form submission with details
            _logger.LogInformation("Form submitted by user: {UserName} at {Time}", 
                UserName, DateTime.UtcNow);
            
            if (string.IsNullOrWhiteSpace(UserName))
            {
                _logger.LogWarning("Form submission failed: Missing username");
                return Page();
            }

            // Processing with audit trail
            _logger.LogInformation("Processing data for user: {UserName}", UserName);
            Success = true;
            
            return Page();
        }
    }
}
