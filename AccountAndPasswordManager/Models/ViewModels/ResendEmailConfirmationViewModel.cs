using System.ComponentModel.DataAnnotations;

namespace AccountAndPasswordManager.Models.ViewModels
{
    public class ResendEmailConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
