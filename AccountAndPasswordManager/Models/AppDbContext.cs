using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace AccountAndPasswordManager.Models;

public partial class AppDbContext : DbContext
{
    public AppDbContext()
    {
    }

    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<CardDetail> CardDetails { get; set; }

    public virtual DbSet<LoginInformation> LoginInformations { get; set; }

    public virtual DbSet<Note> Notes { get; set; }

    public virtual DbSet<Password> Passwords { get; set; }

    public virtual DbSet<User> Users { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see https://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseSqlServer("Server=LAPTOP-PAGJUJU9\\SQLEXPRESS;Database=DB_AccountAndPasswordManager;Trusted_Connection=True;TrustServerCertificate=True;");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<CardDetail>(entity =>
        {
            entity.HasKey(e => e.CardDetailsId).HasName("PK__CardDeta__ACF7D7A866723C02");

            entity.Property(e => e.CardDetailsId).HasColumnName("CardDetailsID");
            entity.Property(e => e.CardName).HasMaxLength(55);
            entity.Property(e => e.CardNameHolder).HasMaxLength(255);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("(getdate())");
            entity.Property(e => e.Description).HasMaxLength(255);
            entity.Property(e => e.EncryptedCardNumber).HasMaxLength(55);
            entity.Property(e => e.EncryptedCvv)
                .HasMaxLength(3)
                .HasColumnName("EncryptedCVV");
            entity.Property(e => e.EncryptedExpiryDate).HasMaxLength(10);
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.User).WithMany(p => p.CardDetails)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_User_CardDetails_UserID");
        });

        modelBuilder.Entity<LoginInformation>(entity =>
        {
            entity.HasKey(e => e.LoginInformationId).HasName("PK__LoginInf__4B5C793413E886CA");

            entity.ToTable("LoginInformation");

            entity.Property(e => e.LoginInformationId).HasColumnName("LoginInformationID");
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("(getdate())");
            entity.Property(e => e.Description).HasMaxLength(255);
            entity.Property(e => e.EncryptedUsername).HasMaxLength(255);
            entity.Property(e => e.Title).HasMaxLength(55);
            entity.Property(e => e.UserId).HasColumnName("UserID");
            entity.Property(e => e.Website).HasMaxLength(255);

            entity.HasOne(d => d.User).WithMany(p => p.LoginInformations)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_User_LoginInformation_UserID");
        });

        modelBuilder.Entity<Note>(entity =>
        {
            entity.HasKey(e => e.NoteId).HasName("PK__Notes__EACE357F74FF1FD9");

            entity.Property(e => e.NoteId).HasColumnName("NoteID");
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("(getdate())");
            entity.Property(e => e.Title).HasMaxLength(55);
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.User).WithMany(p => p.Notes)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_User_Notes_UserID");
        });

        modelBuilder.Entity<Password>(entity =>
        {
            entity.HasKey(e => e.PasswordId).HasName("PK__Password__EA7BF0E8A6EE5AE5");

            entity.Property(e => e.PasswordId).HasColumnName("PasswordID");
            entity.Property(e => e.Description).HasMaxLength(255);
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.User).WithMany(p => p.Passwords)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_User_Passwords_UserID");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId).HasName("PK__Users__3214EC27E1BD3598");

            entity.HasIndex(e => e.Username, "UQ__Users__536C85E4527CD661").IsUnique();

            entity.HasIndex(e => e.Email, "UQ__Users__A9D10534FE9CE73F").IsUnique();

            entity.Property(e => e.UserId).HasColumnName("UserID");
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("(getdate())");
            entity.Property(e => e.Email).HasMaxLength(255);
            entity.Property(e => e.FirstName).HasMaxLength(55);
            entity.Property(e => e.Gender).HasMaxLength(10);
            entity.Property(e => e.IsActive).HasDefaultValue(true);
            entity.Property(e => e.LastName).HasMaxLength(55);
            entity.Property(e => e.MiddleName).HasMaxLength(55);
            entity.Property(e => e.Username).HasMaxLength(255);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
