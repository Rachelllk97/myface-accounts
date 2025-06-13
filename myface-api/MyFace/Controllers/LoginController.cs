using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using MyFace.Models.Request;
using MyFace.Models.Response;
using MyFace.Repositories;
using MyFace.Utilities;
using MyFace.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using MyFace.Models.Database;

namespace MyFace.Controllers
{
    [Authorize]
    [ApiController]
    [Route("/login")]

    public class LoginController
    {
        // [HttpPost("login")]
        // public async Task<IActionResult> Login([FromBody] LoginRequest request)
        // {
        //     var user = await User.FirstOrDefaultAsync(u => u.Username.ToLower() == request.Username.ToLower());
        // }

        // }
    }
}