using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;
using System;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }

        [HttpGet]
        public IActionResult Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        [ActionName("Signup")]
        public async Task <IActionResult> Signup_Post(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
                //user.Attributes.Add(CognitoAttribute.Email.AttributeName, model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Password);

                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
            }
            return View();
        }

        [HttpGet]
        public IActionResult Confirm(ConfirmModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> Confirm_Post(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the give email address was not found");
                    //return View(model);
                }

                //var result = await _userManager.ConfirmEmailAsync(user, model.Code).ConfigureAwait(false);
                var result = await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                        //return View(model);
                    }
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> Login_Post(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and password do not match");
                }
            }
            return View("Login", model);
        }

        [HttpGet]
        public IActionResult ForgotPassword(ForgotPasswordModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword_Post(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);

                if (user == null)
                {
                    ModelState.AddModelError("InvalidEmail", "Could not find a user corresponding to the email provided.");
                    return View(model);
                }

                try
                {
                    await user.ForgotPasswordAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("ForgotPasswordError", ex.Message);
                    return View(model);
                }

                return RedirectToAction("ResetPassword");

            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPassword(ResetPasswordModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("ResetPassword")]
        public async Task<IActionResult> ResetPassword_Post(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);

                if (user == null)
                {
                    ModelState.AddModelError("InvalidEmail", "Could not find a user corresponding to the email provided.");
                    return View(model);
                }

                try
                {
                    await user.ConfirmForgotPasswordAsync(model.Code, model.Password).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("ConfirmForgotPasswordError", ex.Message);
                    return View(model);
                }

                return RedirectToAction("Index", "Home");
            }

            return View(model);
        }
    }
}