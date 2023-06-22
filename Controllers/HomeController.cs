using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using LabMaintanance5.Models;
using System.Security.Cryptography;
using System.Text;

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
            var user = db.AllUsers.SingleOrDefault(u => u.username == username && u.password == password && u.status);
            if (user == null)
            {
                // Authentication failed
                ModelState.AddModelError("", "Invalid username or password");
                return View();
            }
            else
            {
                // Authentication succeeded

                // Store user information in session
                Session["UserId"] = user.user_id;
                Session["Username"] = user.username;
                Session["RoleId"] = user.role_id;

                // Create a cookie to remember the user
                HttpCookie userCookie = new HttpCookie("UserInfo");
                userCookie["UserId"] = user.user_id.ToString();
                userCookie.Expires = DateTime.Now.AddDays(7); // Set the cookie expiration time
                Response.Cookies.Add(userCookie); // Add the cookie to the response

                // Redirect based on user role
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
        public ActionResult Register([Bind(Include = "user_id,username,email,role_id,password")] AllUser allUser)
        {
            // Check if username or email already exists in the database
            var existingUser = db.AllUsers.FirstOrDefault(u => u.username == allUser.username || u.email == allUser.email);
            if (existingUser != null)
            {
                // User with the same username or email already exists
                ModelState.AddModelError("", "Username or email already exists. Please enter a different username and email.");
            }

            if (ModelState.IsValid)
            {
                // Generate hash password
                using (SHA256 sha256Hash = SHA256.Create())
                {
                    byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(allUser.password));
                    StringBuilder builder = new StringBuilder();
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        builder.Append(bytes[i].ToString("x2"));
                    }
                    allUser.hashPassword = builder.ToString();
                }

                allUser.status = true;

                db.AllUsers.Add(allUser);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name", allUser.role_id);
            return View(allUser);
        }

    }
}
