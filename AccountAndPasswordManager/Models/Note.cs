using System;
using System.Collections.Generic;

namespace AccountAndPasswordManager.Models;

public partial class Note
{
    public int NoteId { get; set; }

    public int UserId { get; set; }

    public string Title { get; set; } = null!;

    public string? EncryptedContent { get; set; }

    public DateTime CreatedAt { get; set; }

    public virtual User User { get; set; } = null!;
}
