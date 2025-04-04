using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace PasswordResetPortal.Pages
{
    public class encryptpassModel : PageModel
    {
        [BindProperty] public string Password { get; set; }

        public string Message { get; set; }

        public void OnGet()
        {
        }
        public void OnPost()
        {
            Message = SecurityHelper.Encrypt(Password, "passwordresetportal");
        }
    }
}
