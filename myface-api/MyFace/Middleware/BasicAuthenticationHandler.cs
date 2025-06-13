
using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MyFace.Repositories;
using MyFace.Services;
using MyFace.Utilities;

public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{

    private readonly AuthenticationServices _authService;
    private readonly IUsersRepo _users;


    public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            AuthenticationServices authService,
            IUsersRepo users)
            //Passes options, logger, and encoder to the base class constructor
            : base(options, logger, encoder)
    {


        _authService = authService;
        _users = users;

    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check if the Authorization header is present in the request.
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            // If the Authorization header is missing, fail the authentication with an appropriate message.
            return AuthenticateResult.Fail("Missing Authorization Header");
        }
        // Retrieve the value of the Authorization header.
        var authorizationHeader = Request.Headers["Authorization"].ToString();
        // Attempt to parse the Authorization header into a structured AuthenticationHeaderValue object.
        if (!AuthenticationHeaderValue.TryParse(authorizationHeader, out var headerValue))
        {
            // If parsing fails, the header is considered invalid and authentication fails.
            return AuthenticateResult.Fail("Invalid Authorization Header");
        }

        if (!"Basic".Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            // If the scheme is not "Basic", fail authentication with a relevant message.
            return AuthenticateResult.Fail("Invalid Authorization Scheme");
        }
        // Decode the Base64-encoded credentials from the authorization header parameter.
        // This yields a "username:password" string which is then split by the colon.
        var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(headerValue.Parameter)).Split(':', 2);
        // Check if splitting the credentials results in exactly two components (username and password).
        if (credentials.Length != 2)
        {
            // If not, the credentials are invalid and authentication fails.
            return AuthenticateResult.Fail("Invalid Basic Authentication Credentials");
        }
             // Extract the email (username) and password from the decoded credentials.
            var userName = credentials[0];
            var password = credentials[1];
        try
        {
            // Use the IUserService to validate the user credentials.
            var user = _users.GetByUserName(userName);

             
                if (user == null)
                {
                    return AuthenticateResult.Fail("User not found");
                }


            var salt = user.Salt;
            byte[] saltArray = Convert.FromBase64String(salt);
            var hashGenerator = new HashGenerator();
            var hashedPassword = hashGenerator.GenerateHash(password, saltArray);
              

                if (user.HashedPassword != hashedPassword)
                {
                    return AuthenticateResult.Fail("Invalid password");
                }


                // If no user matches the provided credentials, fail authentication.
    
            // If the credentials are valid, create claims for the user.
            // Claims describe the user (ID, email, roles, etc.).
            var claims = new[]
            {
                    
                    // A unique identifier for the user.
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    // The user's email, stored as their "name" claim.
                    new Claim(ClaimTypes.Name, user.Email)
                };
            // Create a ClaimsIdentity with the specified claims and authentication scheme
            // ClaimsIdentity groups those claims and specifies an authentication type,
            // indicating a single identity the user has.
            var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
            // Create a ClaimsPrincipal based on the ClaimsIdentity
            // ClaimsPrincipal is the container that can hold one or more ClaimsIdentity objects
            // enabling multiple ways a user might be authenticated.
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                
                
                // AuthenticationTicket is the object used by ASP.NET Core to store and
                // track the authenticated user’s ClaimsPrincipal during an authentication session.
                var authenticationTicket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
                // Indicate that authentication was successful and return the ticket
                return AuthenticateResult.Success(authenticationTicket);
            }
            catch
            {
                // If any exception occurs during authentication, fail with a generic error message.
                return AuthenticateResult.Fail("Error occurred during authentication");
            }
        }
    }











