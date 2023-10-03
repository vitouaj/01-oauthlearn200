using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace oauthlearn200.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class ExternalAuthenticationController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;
        
        public ExternalAuthenticationController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IEmailSender mailSender
            )
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = mailSender;
        }

        

        [HttpGet]
        [Route("FacebookLogin")]
        public IActionResult FacebookLogin()
        {
            var provider = "Facebook";
            var redirectUrl = "/api/ExternalAuthentication/CallBack";
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        [Route("GoogleLogin")]
        public IActionResult GoogleLogin()
        {
            var provider = "Google";
            var redirectUrl = "/api/ExternalAuthentication/CallBack";
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }


        [HttpGet]
        [Route("CallBack")]
        public async Task<IActionResult> CallBack(string remoteError = null)
        {
            string returnUrl = Url.Content("~/");
            if (remoteError != null)
            {
                //ErrorMessage = $"Error from external provider: {remoteError}";
                return Redirect("/Identity/Account/Login");
            }
            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {      
                //ErrorMessage = "Error loading external login information.";
                return Redirect("/Identity/Account/Login");
            }

            // Sign in the user with this external login provider if the user already has a login.
            SignInResult result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: true, bypassTwoFactor: true);

            if (result.Succeeded)
            {
                Console.WriteLine($"{info.Principal.Identity.Name} logged in with {info.LoginProvider} provider.");
                return Redirect("/");
            }
            if (result.IsLockedOut)
            {
                return Redirect("/Identity/Account/Login");
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                 //ReturnUrl = returnUrl;
                 //LoginProvider = info.LoginProvider;
                var Email = "";
                var Name = info.Principal.Identity.Name;
                if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                {
                    Email = info.Principal.FindFirstValue(ClaimTypes.Email);
                }
                var user = new IdentityUser { UserName = Email, Email = Email };
                var result2 = await _userManager.CreateAsync(user);
                if (result2.Succeeded)
                {
                    result2 = await _userManager.AddLoginAsync(user, info);
                    if (result2.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);

                        Console.WriteLine($"User created an account using {info.LoginProvider} provider.");

                        var userId = await _userManager.GetUserIdAsync(user);

                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                        var callbackUrl = Url.Page("/Account/ConfirmEmail", pageHandler: null, values: new { area = "Identity", userId = userId, code = code}, protocol: Request.Scheme);

                        await _emailSender.SendEmailAsync(Email, "Confirm your email", $"Please confirm your account by <a href = '{HtmlEncoder.Default.Encode(callbackUrl)}' > clicking here </ a >.");

                        return Redirect("/");
                    }
                }
                foreach (var error in result2.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Redirect("/");
            }
        }
    }
}