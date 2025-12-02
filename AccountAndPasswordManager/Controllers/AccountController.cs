using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using AccountAndPasswordManager.Models.ViewModels;

namespace AccountAndPasswordManager.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        // GET: /Account/Login
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ViewData["ErrorMessage"]?.ToString()))
            {
                ModelState.AddModelError(string.Empty, ViewData["ErrorMessage"].ToString());
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
    
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToAction(nameof(LoginWith2fa), new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                    }
                        if (result.IsLockedOut)
                        {
                            _logger.LogWarning("User account locked out.");
                            return RedirectToAction(nameof(Lockout));
                        }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }
        }

        return View(model);
    }

        // GET: /Account/Register
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var user = new IdentityUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var userId = await _userManager.GetUserIdAsync(user);
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
          
                    var callbackUrl = Url.Action(
                    "ConfirmEmail",
                    "Account",
                    new { userId = userId, code = code, returnUrl = returnUrl },
                    protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToAction(nameof(RegisterConfirmation), new { email = model.Email, returnUrl = returnUrl });
                    }
                
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }

            foreach (var error in result.Errors)
      {
     ModelState.AddModelError(string.Empty, error.Description);
       }
      }

            return View(model);
      }

        // GET: /Account/RegisterConfirmation
        [AllowAnonymous]
        public async Task<IActionResult> RegisterConfirmation(string email, string returnUrl = null)
  {
     if (email == null)
            {
       return RedirectToAction("Index", "Home");
            }

            var user = await _userManager.FindByEmailAsync(email);
       if (user == null)
            {
                return NotFound($"Unable to load user with email '{email}'.");
         }

            ViewData["Email"] = email;
        ViewData["DisplayConfirmAccountLink"] = true;

         if (ViewData["DisplayConfirmAccountLink"] != null && (bool)ViewData["DisplayConfirmAccountLink"])
      {
    var userId = await _userManager.GetUserIdAsync(user);
     var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            
     ViewData["EmailConfirmationUrl"] = Url.Action(
         "ConfirmEmail",
        "Account",
              new { userId = userId, code = code, returnUrl = returnUrl },
           protocol: Request.Scheme);
      }

     return View();
      }

        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
  public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
          if (userId == null || code == null)
    {
        return RedirectToAction("Index", "Home");
            }

     var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
          {
 return NotFound($"Unable to load user with ID '{userId}'.");
       }

code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        var result = await _userManager.ConfirmEmailAsync(user, code);
   
            ViewData["StatusMessage"] = result.Succeeded ? "Thank you for confirming your email." : "Error confirming your email.";
   return View();
        }

    // POST: /Account/Logout
      [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string returnUrl = null)
        {
      await _signInManager.SignOutAsync();
         _logger.LogInformation("User logged out.");
      
    if (returnUrl != null)
  {
                return LocalRedirect(returnUrl);
       }
            else
      {
    return RedirectToAction("LogoutConfirmation", "Account");
       }
        }

        // GET: /Account/LogoutConfirmation
        [AllowAnonymous]
        public IActionResult LogoutConfirmation()
        {
            return View();
   }

        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
       return View();
        }

        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
if (ModelState.IsValid)
            {
            var user = await _userManager.FindByEmailAsync(model.Email);
     if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
      {
    return RedirectToAction(nameof(ForgotPasswordConfirmation));
   }

      var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
        
      var callbackUrl = Url.Action(
            "ResetPassword",
    "Account",
            new { code = code },
   protocol: Request.Scheme);

     await _emailSender.SendEmailAsync(
           model.Email,
           "Reset Password",
           $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                return RedirectToAction(nameof(ForgotPasswordConfirmation));
 }

            return View(model);
        }

        // GET: /Account/ForgotPasswordConfirmation
    [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
 {
        return View();
        }

        // GET: /Account/ResendEmailConfirmation
     [AllowAnonymous]
    public IActionResult ResendEmailConfirmation()
      {
        return View();
        }

        // POST: /Account/ResendEmailConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendEmailConfirmation(ResendEmailConfirmationViewModel model)
        {
     if (!ModelState.IsValid)
        {
      return View(model);
   }

        var user = await _userManager.FindByEmailAsync(model.Email);
       if (user == null)
          {
          ModelState.AddModelError(string.Empty, "Verification email sent. Please check your email.");
     return View(model);
     }

         var userId = await _userManager.GetUserIdAsync(user);
   var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
 
    var callbackUrl = Url.Action(
      "ConfirmEmail",
       "Account",
  new { userId = userId, code = code },
 protocol: Request.Scheme);

        await _emailSender.SendEmailAsync(
    model.Email,
   "Confirm your email",
          $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            ModelState.AddModelError(string.Empty, "Verification email sent. Please check your email.");
        return View(model);
      }

        // GET: /Account/Lockout
        [AllowAnonymous]
        public IActionResult Lockout()
   {
       return View();
    }

        // GET: /Account/LoginWith2fa
    [AllowAnonymous]
        public IActionResult LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
 ViewData["ReturnUrl"] = returnUrl;
    ViewData["RememberMe"] = rememberMe;
     return View();
   }
    }
}
