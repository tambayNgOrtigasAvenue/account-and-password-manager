using System.ComponentModel.DataAnnotations;

namespace AccountAndPasswordManager.Models.ViewModels
{
    public class DashboardViewModel
    {
        public List<Note> Notes { get; set; } = new List<Note>();
        public List<Password> Passwords { get; set; } = new List<Password>();
        public List<CardDetail> Cards { get; set; } = new List<CardDetail>();
        public List<LoginInformation> Logins { get; set; } = new List<LoginInformation>();
    }

    public class CreateNoteViewModel
    {
        [Required]
        [StringLength(55)]
        public string Title { get; set; }

        [Required]
        public string Content { get; set; }
    }

    public class CreatePasswordViewModel
    {
        [Required]
        public string PasswordValue { get; set; }

        [StringLength(255)]
        public string Description { get; set; }
    }

    public class CreateCardViewModel
    {
        [Required]
        [StringLength(55)]
        public string CardName { get; set; } // e.g. "Chase Visa"

        [StringLength(255)]
        public string CardHolderName { get; set; }

        [Required]
        [CreditCard]
        public string CardNumber { get; set; }

        [Required]
        public string ExpiryDate { get; set; } // MM/YY

        [Required]
        [StringLength(4, MinimumLength = 3)]
        public string CVV { get; set; }

        public string Description { get; set; }
    }

    public class CreateLoginViewModel
    {
        [StringLength(55)]
        public string Title { get; set; } // e.g. "Facebook"

        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }

        [Url]
        public string Website { get; set; }

        public string Description { get; set; }
    }

    public class EditNoteViewModel : CreateNoteViewModel
    {
        public int NoteId { get; set; }
    }

    public class EditPasswordViewModel : CreatePasswordViewModel
    {
        public int PasswordId { get; set; }
    }

    public class EditCardViewModel : CreateCardViewModel
    {
        public int CardDetailsId { get; set; }
    }

    public class EditLoginViewModel : CreateLoginViewModel
    {
        public int LoginInformationId { get; set; }
    }
}
