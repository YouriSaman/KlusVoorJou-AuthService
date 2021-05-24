using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthService.DAL;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Controllers
{
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly AuthDbContext _dbContext;
        private readonly ITokenBuilder _tokenBuilder;

        public AuthController(AuthDbContext dbContext, ITokenBuilder tokenBuilder)
        {
            _dbContext = dbContext;
            _tokenBuilder = tokenBuilder;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] User user)
        {
            var dbUser = await _dbContext
                .Users
                .SingleOrDefaultAsync(u => u.Username == user.Username);

            if (dbUser == null)
            {
                return NotFound("User not found.");
            }

            // For testing only: add hashed passwords
            var isValid = dbUser.Password == user.Password;

            if (!isValid)
            {
                return BadRequest("Could not authenticate user.");
            }

            var token = _tokenBuilder.BuildToken(user.Username);

            return Ok(token);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User user)
        {
            user.Id = Guid.NewGuid();

            await _dbContext.Users.AddAsync(user);
            await _dbContext.SaveChangesAsync();

            return Ok(user);
        }

        [HttpGet("verify")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> VerifyToken()
        {
            var username = User
                .Claims
                .SingleOrDefault();

            if (username == null)
            {
                return Unauthorized();
            }

            var userExists = await _dbContext
                .Users
                .AnyAsync(u => u.Username == username.Value);

            if (!userExists)
            {
                return Unauthorized();
            }

            return NoContent();
        }
    }
}
