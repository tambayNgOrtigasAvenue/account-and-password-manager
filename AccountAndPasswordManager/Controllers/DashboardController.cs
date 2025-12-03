using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AccountAndPasswordManager.Models;
using AccountAndPasswordManager.Models.ViewModels;
using AccountAndPasswordManager.Services;

namespace AccountAndPasswordManager.Controllers
{
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly AppDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEncryptionService _encryptionService;

        public DashboardController(AppDbContext context, UserManager<IdentityUser> userManager, IEncryptionService encryptionService)
        {
            _context = context;
            _userManager = userManager;
            _encryptionService = encryptionService;
        }

        // Helper to get or create the business user
        private async Task<User> GetCurrentUserAsync()
        {
            var identityUser = await _userManager.GetUserAsync(User);
            if (identityUser == null) return null;

            var user = await _context.ApplicationUsers
                .Include(u => u.Notes)
                .Include(u => u.Passwords)
                .Include(u => u.CardDetails)
                .Include(u => u.LoginInformations)
                .FirstOrDefaultAsync(u => u.Email == identityUser.Email);

            if (user == null)
            {
                // Lazy creation of the business user entry
                user = new User
                {
                    Email = identityUser.Email,
                    Username = identityUser.UserName,
                    FirstName = "User", // Default
                    LastName = "Name", // Default
                    PasswordHash = "-", // Not used since we use Identity
                    Gender = "N/A",
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true,
                    IsVerified = true
                };
                _context.ApplicationUsers.Add(user);
                await _context.SaveChangesAsync();
            }

            return user;
        }

        public async Task<IActionResult> Index()
        {
            var user = await GetCurrentUserAsync();
            if (user == null) return RedirectToAction("Login", "Account");

            // Decrypt data for display
            foreach (var note in user.Notes)
            {
                note.EncryptedContent = _encryptionService.Decrypt(note.EncryptedContent);
            }

            foreach (var pass in user.Passwords)
            {
                pass.EncryptedPassword = _encryptionService.Decrypt(pass.EncryptedPassword);
            }

            foreach (var card in user.CardDetails)
            {
                card.EncryptedCardNumber = _encryptionService.Decrypt(card.EncryptedCardNumber);
                card.EncryptedExpiryDate = _encryptionService.Decrypt(card.EncryptedExpiryDate);
                card.EncryptedCvv = _encryptionService.Decrypt(card.EncryptedCvv);
            }

            foreach (var login in user.LoginInformations)
            {
                login.EncryptedUsername = _encryptionService.Decrypt(login.EncryptedUsername);
                login.EncryptedPasswordHash = _encryptionService.Decrypt(login.EncryptedPasswordHash);
            }

            var model = new DashboardViewModel
            {
                Notes = user.Notes.ToList(),
                Passwords = user.Passwords.ToList(),
                Cards = user.CardDetails.ToList(),
                Logins = user.LoginInformations.ToList()
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateNote(CreateNoteViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var note = new Note
                {
                    UserId = user.UserId,
                    Title = model.Title,
                    EncryptedContent = _encryptionService.Encrypt(model.Content),
                    CreatedAt = DateTime.UtcNow
                };
                _context.Notes.Add(note);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreatePassword(CreatePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var password = new Password
                {
                    UserId = user.UserId,
                    EncryptedPassword = _encryptionService.Encrypt(model.PasswordValue),
                    Description = model.Description
                };
                _context.Passwords.Add(password);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateCard(CreateCardViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var card = new CardDetail
                {
                    UserId = user.UserId,
                    CardName = model.CardName,
                    CardNameHolder = model.CardHolderName,
                    EncryptedCardNumber = _encryptionService.Encrypt(model.CardNumber),
                    EncryptedExpiryDate = _encryptionService.Encrypt(model.ExpiryDate),
                    EncryptedCvv = _encryptionService.Encrypt(model.CVV),
                    Description = model.Description,
                    CreatedAt = DateTime.UtcNow
                };
                _context.CardDetails.Add(card);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateLogin(CreateLoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var login = new LoginInformation
                {
                    UserId = user.UserId,
                    Title = model.Title,
                    EncryptedUsername = _encryptionService.Encrypt(model.Username),
                    EncryptedPasswordHash = _encryptionService.Encrypt(model.Password),
                    Website = model.Website,
                    Description = model.Description,
                    CreatedAt = DateTime.UtcNow
                };
                _context.LoginInformations.Add(login);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return RedirectToAction(nameof(Index));
        }

        // ================= EDIT & DELETE ACTIONS =================

        // --- NOTES ---
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditNote(EditNoteViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var item = await _context.Notes.FirstOrDefaultAsync(x => x.NoteId == model.NoteId && x.UserId == user.UserId);
                if (item != null)
                {
                    item.Title = model.Title;
                    item.EncryptedContent = _encryptionService.Encrypt(model.Content);
                    await _context.SaveChangesAsync();
                }
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteNote(int id)
        {
            var user = await GetCurrentUserAsync();
            var item = await _context.Notes.FirstOrDefaultAsync(x => x.NoteId == id && x.UserId == user.UserId);
            if (item != null)
            {
                _context.Notes.Remove(item);
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }

        // --- PASSWORDS ---
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditPassword(EditPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var item = await _context.Passwords.FirstOrDefaultAsync(x => x.PasswordId == model.PasswordId && x.UserId == user.UserId);
                if (item != null)
                {
                    item.EncryptedPassword = _encryptionService.Encrypt(model.PasswordValue);
                    item.Description = model.Description;
                    await _context.SaveChangesAsync();
                }
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeletePassword(int id)
        {
            var user = await GetCurrentUserAsync();
            var item = await _context.Passwords.FirstOrDefaultAsync(x => x.PasswordId == id && x.UserId == user.UserId);
            if (item != null)
            {
                _context.Passwords.Remove(item);
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }

        // --- CARDS ---
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditCard(EditCardViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var item = await _context.CardDetails.FirstOrDefaultAsync(x => x.CardDetailsId == model.CardDetailsId && x.UserId == user.UserId);
                if (item != null)
                {
                    item.CardName = model.CardName;
                    item.CardNameHolder = model.CardHolderName;
                    item.EncryptedCardNumber = _encryptionService.Encrypt(model.CardNumber);
                    item.EncryptedExpiryDate = _encryptionService.Encrypt(model.ExpiryDate);
                    item.EncryptedCvv = _encryptionService.Encrypt(model.CVV);
                    item.Description = model.Description;
                    await _context.SaveChangesAsync();
                }
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteCard(int id)
        {
            var user = await GetCurrentUserAsync();
            var item = await _context.CardDetails.FirstOrDefaultAsync(x => x.CardDetailsId == id && x.UserId == user.UserId);
            if (item != null)
            {
                _context.CardDetails.Remove(item);
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }

        // --- LOGINS ---
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditLogin(EditLoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await GetCurrentUserAsync();
                var item = await _context.LoginInformations.FirstOrDefaultAsync(x => x.LoginInformationId == model.LoginInformationId && x.UserId == user.UserId);
                if (item != null)
                {
                    item.Title = model.Title;
                    item.EncryptedUsername = _encryptionService.Encrypt(model.Username);
                    item.EncryptedPasswordHash = _encryptionService.Encrypt(model.Password);
                    item.Website = model.Website;
                    item.Description = model.Description;
                    await _context.SaveChangesAsync();
                }
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteLogin(int id)
        {
            var user = await GetCurrentUserAsync();
            var item = await _context.LoginInformations.FirstOrDefaultAsync(x => x.LoginInformationId == id && x.UserId == user.UserId);
            if (item != null)
            {
                _context.LoginInformations.Remove(item);
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }
    }
}