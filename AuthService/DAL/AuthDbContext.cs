using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthService.DAL
{
    public class AuthDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
            Database.Migrate();
        }
    }
}
