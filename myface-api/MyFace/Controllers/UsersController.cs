using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using MyFace.Models.Request;
using MyFace.Models.Response;
using MyFace.Repositories;
using MyFace.Utilities;
using MyFace.Services;
using Microsoft.AspNetCore.Authorization;

namespace MyFace.Controllers
{
    
    [Authorize]
    [ApiController]
    [Route("/users")]
    public class UsersController : ControllerBase
    {
        private readonly IUsersRepo _users;

         private readonly AuthenticationServices _authService;

        public UsersController(IUsersRepo users, AuthenticationServices authenticationService)
        {
            _users = users;
            _authService = authenticationService;
        }
        
        [HttpGet("")]
        public ActionResult<UserListResponse> Search([FromQuery] UserSearchRequest searchRequest)
        {
            var users = _users.Search(searchRequest);
            var userCount = _users.Count(searchRequest);
            return UserListResponse.Create(searchRequest, users, userCount);
        }

        [HttpGet("{id}")]
        public ActionResult<UserResponse> GetById([FromRoute] int id)
        {
            
                var user = _users.GetById(id);
                return Ok(new UserResponse(user));
            
            }
        


        [HttpPost("create")]
        public IActionResult Create([FromBody] CreateUserRequest newUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var saltGenerator = new SaltGenerator();
            var hashGenerator = new HashGenerator();
            byte[] saltArray = saltGenerator.GenerateSalt();
            string salt = Convert.ToBase64String(saltArray);
            string hashedPassword = hashGenerator.GenerateHash(newUser.Password, saltArray);
            var user = _users.Create(newUser, hashedPassword, salt );

            var url = Url.Action("GetById", new { id = user.Id });
            var responseViewModel = new UserResponse(user);
            
            return Created(url, responseViewModel);
        }

        [HttpPatch("{id}/update")]
        public ActionResult<UserResponse> Update([FromRoute] int id, [FromBody] UpdateUserRequest update)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = _users.Update(id, update);
            return new UserResponse(user);
        }
        
        [HttpDelete("{id}")]
        public IActionResult Delete([FromRoute] int id)
        {
            _users.Delete(id);
            return Ok();
        }
    }
}