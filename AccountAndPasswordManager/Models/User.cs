using System;
using System.Collections.Generic;

namespace AccountAndPasswordManager.Models;

public partial class User
{
    public int UserId { get; set; }

    public string LastName { get; set; } = null!;

    public string FirstName { get; set; } = null!;

    public string? MiddleName { get; set; }

    public DateOnly BirthDate { get; set; }

    public string Gender { get; set; } = null!;

    public string Username { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string PasswordHash { get; set; } = null!;

    public DateTime CreatedAt { get; set; }

    public bool IsVerified { get; set; }

    public bool IsActive { get; set; }

    public virtual ICollection<CardDetail> CardDetails { get; set; } = new List<CardDetail>();

    public virtual ICollection<LoginInformation> LoginInformations { get; set; } = new List<LoginInformation>();

    public virtual ICollection<Note> Notes { get; set; } = new List<Note>();

    public virtual ICollection<Password> Passwords { get; set; } = new List<Password>();
}
