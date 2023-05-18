using angular_auth_api.Context;
using angular_auth_api.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
            
            // Check if a body field is not null
            // if (string.IsNullOrEmpty(userObj.Username)) { }

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User registered successfully."
            });
        }
    }
}
