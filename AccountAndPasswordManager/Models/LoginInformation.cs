using System;
using System.Collections.Generic;

namespace AccountAndPasswordManager.Models;

public partial class LoginInformation
{
    public int LoginInformationId { get; set; }

    public int UserId { get; set; }

    public string? Title { get; set; }

    public string EncryptedUsername { get; set; } = null!;

    public string EncryptedPasswordHash { get; set; } = null!;

    public string? EncryptedSecretKey { get; set; }

    public string? Website { get; set; }

    public string? Description { get; set; }

    public byte[]? Attachment { get; set; }

    public DateTime CreatedAt { get; set; }

    public virtual User User { get; set; } = null!;
}
