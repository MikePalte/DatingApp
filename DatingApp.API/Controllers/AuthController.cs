
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.DTOs;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;

        }

        [HttpPost("register")]

        public async Task<IActionResult> Register(UserForRegisterDTO userForRegisterDTO)
        {
            userForRegisterDTO.Username = userForRegisterDTO.Username.ToLower();

            if (await _repo.UserExists(userForRegisterDTO.Username))
                return BadRequest("Username already exists");

            var userToCreate = new User
            {
                Username = userForRegisterDTO.Username
            };

            var createdUser = await _repo.Register(userToCreate, userForRegisterDTO.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDTO userForLoginDTO)
        {
            

            //Checking to make sure we have a user and that there username and password is stored in the database
            var userFromRepo = await _repo.Login(userForLoginDTO.Username.ToLower(), userForLoginDTO.Password);

            if (userFromRepo == null)
                return Unauthorized();

            //The token contains two claims the users Id and the users username
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };
            
            //In order to make the token is a valid token when it comes back the server needs to sign the token
            //Creating a key as apart of the sign in credentials
            //We then encrypt this key with a hashing algorithm 
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //Creating the token
            //Passing in the claims
            //Giving it an expire date of 1 day
            // Then passing it the credentials we created above
            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            //Use the tokenhandler to create and write the token
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(new{
                token = tokenHandler.WriteToken(token)
            });
        }
    }
}