using System;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using LabMaintanance5.Models;

namespace LabMaintanance5.Controllers
{
    public class HomeController : Controller
    {
        private LabMaintanance4Entities db = new LabMaintanance4Entities();

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";
            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";
            return View();
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string username, string password)
        {
            var user = db.AllUsers.SingleOrDefault(u => u.username == username && u.status);
            if (user == null || user.hashPassword != ComputeHash(password))
            {
                ModelState.AddModelError("", "Invalid username or password");
                return View();
            }
            else
            {
                Session["UserId"] = user.user_id;
                Session["Username"] = user.username;
                Session["RoleId"] = user.role_id;

                HttpCookie userCookie = new HttpCookie("UserInfo");
                userCookie["UserId"] = user.user_id.ToString();
                userCookie.Expires = DateTime.Now.AddDays(7);
                Response.Cookies.Add(userCookie);

                switch (user.role_id)
                {
                    case 1:
                        return RedirectToAction("Index", "Teacher");
                    case 2:
                        return RedirectToAction("Index", "Stuff");
                    case 3:
                        return RedirectToAction("Index", "Student");
                    default:
                        return RedirectToAction("Index", "Home");
                }
            }
        }

        public ActionResult Register()
        {
            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register([Bind(Include = "user_id,username,email,role_id,password")] AllUser allUser)
        {
            if (ModelState.IsValid)
            {
                if (db.AllUsers.Any(u => u.username == allUser.username) || db.AllUsers.Any(u => u.email == allUser.email))
                {
                    ModelState.AddModelError("", "Username or email already exists. Please choose a different one.");
                    ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name", allUser.role_id);
                    return View(allUser);
                }

                var otp = new Random().Next(1000, 9999);

                allUser.hashPassword = ComputeHash(allUser.password);
                allUser.status = false;
                allUser.email_verified = false;

                db.AllUsers.Add(allUser);
                await db.SaveChangesAsync();

                var email = allUser.email;
                var subject = "Email Verification";
                var body = $"Your verification code is: {otp}";

                await SendEmail(email, subject, body);

                Session["RegisteredEmail"] = email;
                Session["EmailVerificationOTP"] = otp;

                return RedirectToAction("VerifyEmail");
            }

            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name", allUser.role_id);
            return View(allUser);
        }

        public async Task<ActionResult> SendEmail(string email, string subject, string body)
        {
            try
            {
                var smtpClient = new SmtpClient("smtp.gmail.com")
                {
                    Port = 587,
                    Credentials = new NetworkCredential("soumaykanti2859@gmail.com", "ssatuysevdkgrthi"),
                    EnableSsl = true
                };

                using (var message = new MailMessage("soumaykanti2859@gmail.com", email)
                {
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                })
                {
                    await smtpClient.SendMailAsync(message);
                }

                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                // Handle exception and display appropriate error message
                ModelState.AddModelError("", "Failed to send email. Please try again later.");
                return RedirectToAction("Index");
            }
        }

        public ActionResult VerifyEmail()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult VerifyEmail(string otp)
        {
            var enteredOTP = int.Parse(otp);
            var savedOTP = (int)Session["EmailVerificationOTP"];
            if (enteredOTP == savedOTP)
            {
                var email = Session["RegisteredEmail"].ToString();

                var user = db.AllUsers.SingleOrDefault(u => u.email == email);
                if (user != null)
                {
                    user.status = true;
                    user.email_verified = true;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                }

                TempData["SuccessMessage"] = "Email verified successfully!";
                return RedirectToAction("Login");
            }

            ModelState.AddModelError("", "Invalid OTP. Please try again.");
            return View();
        }

        private string ComputeHash(string input)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
