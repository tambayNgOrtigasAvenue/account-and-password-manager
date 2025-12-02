using System.ComponentModel.DataAnnotations;

namespace AccountAndPasswordManager.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
   [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
