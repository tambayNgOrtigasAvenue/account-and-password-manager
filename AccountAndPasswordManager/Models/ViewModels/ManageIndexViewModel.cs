using System.ComponentModel.DataAnnotations;

namespace AccountAndPasswordManager.Models.ViewModels
{
    public class ManageIndexViewModel
    {
   public string Username { get; set; }

        [Phone]
        [Display(Name = "Phone number")]
  public string PhoneNumber { get; set; }
    }
}
