using BackEnd.Api.Config;
using BackEnd.Api.Data;
using BackEnd.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BackEnd.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticatController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _config;

        //// Constructor
        public AuthenticatController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
        }

        ///// <summary>
        ///// Register
        ///// </summary>
        ///// <param name="registerDto"></param>
        ///// <returns></returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = new ApplicationUser { UserName = registerDto.UserName, Email = registerDto.Email };

                var result = await _userManager.CreateAsync(user, registerDto.Password);

                if (result.Succeeded)
                {
                    return Ok(new { Result = result, StatusCode = 200, StatusLebel = "Succes" });
                }

                return BadRequest(result.Errors);
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        ///// <summary>
        ///// Login
        ///// </summary>
        ///// <param name="loginDto"></param>
        ///// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            try
            {

                if (!ModelState.IsValid) { return BadRequest(ModelState); }

                var result = await _signInManager.PasswordSignInAsync(loginDto.UserName, loginDto.Password, false, false);

                if (result.Succeeded)
                {
                    var appUser = await _userManager.FindByNameAsync(loginDto.UserName);
                    var token = GenerateJwtToken(appUser);
                    return Ok(new { Token = token, StatusCode = 200, StatusLabel = "Succes" });
                }

                return Unauthorized();
            }
            catch (Exception ex)
            {

                return BadRequest(ex);
            }

        }


        public string GenerateJwtToken(ApplicationUser user)
        {
            // Define the claims for the token
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            // Retrieve the security key from configuration and ensure it is sufficiently long
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));

            // Create signing credentials using the security key and HMACSHA256 algorithm
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Create the token
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"], // Set the issuer
                audience: _config["Jwt:Issuer"], // Set the audience
                claims: claims, // Add claims
                expires: DateTime.Now.AddMinutes(30), // Set the token expiration time
                signingCredentials: creds); // Add signing credentials

            // Generate the token string
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
