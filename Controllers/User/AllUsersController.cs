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

namespace LabMaintanance5.Controllers.User
{
    public class AllUsersController : Controller
    {
        private LabMaintanance4Entities db = new LabMaintanance4Entities();

        // GET: AllUsers
        public ActionResult Index()
        {
            var allUsers = db.AllUsers.Include(a => a.Role);
            return View(allUsers.ToList());
        }

        // GET: AllUsers/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AllUser allUser = db.AllUsers.Find(id);
            if (allUser == null)
            {
                return HttpNotFound();
            }
            return View(allUser);
        }

        // GET: AllUsers/Create
        public ActionResult Create()
        {
            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name");
            return View();
        }

        // POST: AllUsers/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "user_id,username,email,role_id,password,hashPassword,status")] AllUser allUser)
        {
            if (ModelState.IsValid)
            {
                db.AllUsers.Add(allUser);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name", allUser.role_id);
            return View(allUser);
        }

        // GET: AllUsers/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AllUser allUser = db.AllUsers.Find(id);
            if (allUser == null)
            {
                return HttpNotFound();
            }
            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name", allUser.role_id);
            return View(allUser);
        }

        // POST: AllUsers/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "user_id,username,email,role_id,password,hashPassword,status")] AllUser allUser)
        {
            if (ModelState.IsValid)
            {
                db.Entry(allUser).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            ViewBag.role_id = new SelectList(db.Roles, "role_id", "role_name", allUser.role_id);
            return View(allUser);
        }

        // GET: AllUsers/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AllUser allUser = db.AllUsers.Find(id);
            if (allUser == null)
            {
                return HttpNotFound();
            }
            return View(allUser);
        }


        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            AllUser allUser = db.AllUsers.Find(id);
            db.AllUsers.Remove(allUser);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
        //GET:
       
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
