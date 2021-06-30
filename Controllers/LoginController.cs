using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using jwt_authentication_in_dotnet_5.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace jwt_authentication_in_dotnet_5.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet("Login")]
        public IActionResult Login(string username, string password)
        {
            UserModel login = new UserModel() { Username = username, Password = password };
            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);

            if (null != user)
            {
                var tokenStr = GenerateJwtToken(user);
                response = Ok(new { token = tokenStr });
            }

            return response;
        }

        private string GenerateJwtToken(UserModel user)
        {
            var jwtKey = _config["Jwt:Key"];
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email, user.Email),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials
                );

                
            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);

            return encodedToken;

        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            if (login.Username == "mrtkprc" && login.Password == "123")
            {
                user = new UserModel()
                    {Username = login.Username, Password = login.Password, Email = "mrtkprc@gmail.com"};
            }

            return user;
        }

        [Authorize]
        [HttpPost("Post")]
        public IActionResult Post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            IList<Claim> claim = identity.Claims.ToList();

            var userName = claim[0].Value;

            return Ok(new {text = $"Welcome to {userName}"});
        }

        //This are is not secure due to non-existing "Authorize" annotation.
        [HttpGet("Values")]
        public ActionResult<IEnumerable<string>> GetValues()
        {
            return new[] { "Value1", "Value2" };
        }
    }
}
