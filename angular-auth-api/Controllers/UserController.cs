using angular_auth_api.Context;
using angular_auth_api.Helpers;
using angular_auth_api.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

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

        /* 1. Login User  **/
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null) 
            {
                return BadRequest();
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(x=>x.Username == userObj.Username);
            if (user == null)
            {
                return NotFound(new { Message = "User not found!" });
            }

            if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = "Password is incorrect" });
            }

            user.Token = CreateJwt(user);

            return Ok(new
            {
                Token = user.Token,
                Message = "Login successful."
            });
        }

        /* 2. Register User  **/
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

        /** i. Check if field exists (Method 1) **/
        //private async Task<bool> CheckUserNameExistAsync(string username)
        //{
        //    return await _authContext.Users.AnyAsync(x => x.Username == username);
        //}

        /* ii. Check if field exists (Method 2) **/
        private Task<bool> CheckUserNameExistAsync(string username)
            => _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckUserEmailExistAsync(string email)
            => _authContext.Users.AnyAsync(x => x.Email == email);

        /* iii. Enforce password strength **/
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

        /* iv. Create JWT token **/
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials,
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor); 
            return jwtTokenHandler.WriteToken(token);
        }

        /* 3. Get All Users **/
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}
