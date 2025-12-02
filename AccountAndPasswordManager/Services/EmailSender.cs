using Microsoft.AspNetCore.Identity.UI.Services;

namespace AccountAndPasswordManager.Services
{
    public class EmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // TODO: Implement actual email sending logic
            // For now, just log it
            Console.WriteLine($"Email to: {email}, Subject: {subject}");
            Console.WriteLine($"Message: {htmlMessage}");
            return Task.CompletedTask;
        }
    }
}
