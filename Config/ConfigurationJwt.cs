using BackEnd.Api.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BackEnd.Api.Config
{
    public class ConfigurationJwt
    {
        private readonly IConfiguration _config;

        public ConfigurationJwt(IConfiguration configuration)
        {
            _config = configuration;
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
