using System;
using System.Collections.Generic;

namespace AccountAndPasswordManager.Models;

public partial class CardDetail
{
    public int CardDetailsId { get; set; }

    public int UserId { get; set; }

    public string CardName { get; set; } = null!;

    public string? CardNameHolder { get; set; }

    public string EncryptedCardNumber { get; set; } = null!;

    public string EncryptedExpiryDate { get; set; } = null!;

    public string EncryptedCvv { get; set; } = null!;

    public string? Description { get; set; }

    public DateTime CreatedAt { get; set; }

    public virtual User User { get; set; } = null!;
}
