using System.ComponentModel.DataAnnotations;

namespace BackEnd.Api.Models
{
    public class LoginDto
    {
        [Required] public string UserName { get; set; } = string.Empty;
        [Required] public string Password { get; set; } = string.Empty;

    }
    public class RegisterDto
    {
        [Required] public string UserName { get; set; } = string.Empty;
        [Required] public string Email { get; set; } = string.Empty;
        [Required] public string Password { get; set; } = string.Empty;
    }
}
