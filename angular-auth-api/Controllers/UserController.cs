using angular_auth_api.Context;
using angular_auth_api.Helpers;
using angular_auth_api.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace angular_auth_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null) 
            {
                return BadRequest();
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(x=>x.Username == userObj.Username && x.Password == userObj.Password);
            if (user == null)
            {
                return NotFound(new { Message = "User not found!" });
            }

            return Ok(new
            {
                Message = "Login successful."
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            // Check if object body is not null
            if (userObj == null)
            {
                return BadRequest();
            }

            // Field validations (username[unique], email[unique], password[strength])
            if (await CheckUserNameExistAsync(userObj.Username))
                return BadRequest(new
                {
                    Message = "Username already exists in the database."
                });

            if (await CheckUserEmailExistAsync(userObj.Email))
                return BadRequest(new
                {
                    Message = "Email already exists in the database."
                });

            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            // Check if a body field is not null
            // if (string.IsNullOrEmpty(userObj.Username)) { }

            // Hash password
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);

            // Assign default role as 'user'
            userObj.Role = "User";

            // Assign token as empty string
            userObj.Token = "";

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User registered successfully."
            });
        }

        // Check if field exists (Method 1)
        //private async Task<bool> CheckUserNameExistAsync(string username)
        //{
        //    return await _authContext.Users.AnyAsync(x => x.Username == username);
        //}

        // Check if field exists (Method 2)
        private Task<bool> CheckUserNameExistAsync(string username)
            => _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckUserEmailExistAsync(string email)
            => _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append("Minimum password length should be 8 characters." + Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be alphanumeric and contain both upper and lower case characterers." + Environment.NewLine);

            if (!(Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]")))
                sb.Append("Password should contain special characters" + Environment.NewLine);

            return sb.ToString();
        }
    }
}
