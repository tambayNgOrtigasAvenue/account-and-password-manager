using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AccountAndPasswordManager.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    UserID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    LastName = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: false),
                    FirstName = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: false),
                    MiddleName = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: true),
                    BirthDate = table.Column<DateOnly>(type: "date", nullable: false),
                    Gender = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: false),
                    Username = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "(getdate())"),
                    IsVerified = table.Column<bool>(type: "bit", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false, defaultValue: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK__Users__3214EC27E1BD3598", x => x.UserID);
                });

            migrationBuilder.CreateTable(
                name: "CardDetails",
                columns: table => new
                {
                    CardDetailsID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserID = table.Column<int>(type: "int", nullable: false),
                    CardName = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: false),
                    CardNameHolder = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    EncryptedCardNumber = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: false),
                    EncryptedExpiryDate = table.Column<string>(type: "nvarchar(10)", maxLength: 10, nullable: false),
                    EncryptedCVV = table.Column<string>(type: "nvarchar(3)", maxLength: 3, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "(getdate())")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK__CardDeta__ACF7D7A866723C02", x => x.CardDetailsID);
                    table.ForeignKey(
                        name: "FK_User_CardDetails_UserID",
                        column: x => x.UserID,
                        principalTable: "Users",
                        principalColumn: "UserID");
                });

            migrationBuilder.CreateTable(
                name: "LoginInformation",
                columns: table => new
                {
                    LoginInformationID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserID = table.Column<int>(type: "int", nullable: false),
                    Title = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: true),
                    EncryptedUsername = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    EncryptedPasswordHash = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EncryptedSecretKey = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Website = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    Description = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    Attachment = table.Column<byte[]>(type: "varbinary(max)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "(getdate())")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK__LoginInf__4B5C793413E886CA", x => x.LoginInformationID);
                    table.ForeignKey(
                        name: "FK_User_LoginInformation_UserID",
                        column: x => x.UserID,
                        principalTable: "Users",
                        principalColumn: "UserID");
                });

            migrationBuilder.CreateTable(
                name: "Notes",
                columns: table => new
                {
                    NoteID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserID = table.Column<int>(type: "int", nullable: false),
                    Title = table.Column<string>(type: "nvarchar(55)", maxLength: 55, nullable: false),
                    EncryptedContent = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "(getdate())")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK__Notes__EACE357F74FF1FD9", x => x.NoteID);
                    table.ForeignKey(
                        name: "FK_User_Notes_UserID",
                        column: x => x.UserID,
                        principalTable: "Users",
                        principalColumn: "UserID");
                });

            migrationBuilder.CreateTable(
                name: "Passwords",
                columns: table => new
                {
                    PasswordID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserID = table.Column<int>(type: "int", nullable: false),
                    EncryptedPassword = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK__Password__EA7BF0E8A6EE5AE5", x => x.PasswordID);
                    table.ForeignKey(
                        name: "FK_User_Passwords_UserID",
                        column: x => x.UserID,
                        principalTable: "Users",
                        principalColumn: "UserID");
                });

            migrationBuilder.CreateIndex(
                name: "UQ__Users__536C85E4527CD661",
                table: "Users",
                column: "Username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "UQ__Users__A9D10534FE9CE73F",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CardDetails_UserID",
                table: "CardDetails",
                column: "UserID");

            migrationBuilder.CreateIndex(
                name: "IX_LoginInformation_UserID",
                table: "LoginInformation",
                column: "UserID");

            migrationBuilder.CreateIndex(
                name: "IX_Notes_UserID",
                table: "Notes",
                column: "UserID");

            migrationBuilder.CreateIndex(
                name: "IX_Passwords_UserID",
                table: "Passwords",
                column: "UserID");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "CardDetails");
            migrationBuilder.DropTable(name: "LoginInformation");
            migrationBuilder.DropTable(name: "Notes");
            migrationBuilder.DropTable(name: "Passwords");
            migrationBuilder.DropTable(name: "Users");
        }
    }
}