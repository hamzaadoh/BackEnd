using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BackEnd.Api.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {

        // Const 
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            
        }

        
    }
    public class ApplicationUser : IdentityUser { }
}
