using System;
using System.Collections.Generic;

namespace AccountAndPasswordManager.Models;

public partial class Password
{
    public int PasswordId { get; set; }

    public int UserId { get; set; }

    public string EncryptedPassword { get; set; } = null!;

    public string? Description { get; set; }

    public virtual User User { get; set; } = null!;
}
