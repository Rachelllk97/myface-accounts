
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Authorization.Policy;
// using Microsoft.AspNetCore.Http;

// using MyFace.Services;

// public class AuthenticationMiddleware : I
// {
//     private readonly AuthorizationMiddlewareResultHandler defaultHandler = new();

//     private readonly AuthenticationServices _authService;

//     public AuthenticationMiddleware(AuthenticationServices authService)
//     {

//         _authService = authService;
//     }
//     public async Task HandleAsync(
//         RequestDelegate next,
//         HttpContext context,
//         AuthorizationPolicy policy,
//         PolicyAuthorizationResult authorizeResult)

//     {

//     // If the authorization was forbidden and the resource had a specific requirement,
//     // provide a custom 404 response.
//     var token = _authService.CheckAuthorizationHeader(context.Request);

//     var authenticated = _authService.IsUserAuthenticated(token);
    
//     if(token == null && !authenticated) {
//         context.Response.StatusCode = StatusCodes.Status404NotFound;
//         await context.Response.WriteAsync("Unauthorized request");
//         return;
//     }

//     // // if (authorizeResult.Forbidden
//     // //     && authorizeResult.AuthorizationFailure!.FailedRequirements
//     // //         .OfType<Show404Requirement>().Any())
//     // {
//     //     // Return a 404 to make it appear as if the resource doesn't exist.
//     //     context.Response.StatusCode = StatusCodes.Status404NotFound;
//     //     return;


//         // Fall back to the default implementation.
//         await defaultHandler.HandleAsync(next, context, policy, authorizeResult);

// }
// }

    


