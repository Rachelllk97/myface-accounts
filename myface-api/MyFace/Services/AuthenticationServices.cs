using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using MyFace.Controllers;
using MyFace.Models.Database;
using MyFace.Repositories;
using MyFace.Utilities;

namespace MyFace.Services
{

    public class AuthenticationServices
    {
        private readonly IUsersRepo _users;

        public AuthenticationServices(IUsersRepo users)
        {
            _users = users;
        }

        public bool IsUserAuthenticated(string credentials)
        {

            var encoding = Encoding.GetEncoding("iso-8859-1");
            credentials = encoding.GetString(Convert.FromBase64String(credentials));

            int separator = credentials.IndexOf(':');
            string userName = credentials.Substring(0, separator);
            string password = credentials.Substring(separator + 1);
            var user = _users.GetByUserName(userName);
            var salt = user.Salt;
            byte[] saltArray = Convert.FromBase64String(salt);
            var hashGenerator = new HashGenerator();
            var hashedPassword = hashGenerator.GenerateHash(password, saltArray);

            return user.HashedPassword == hashedPassword;

        }

        public string CheckAuthorizationHeader(HttpRequest request)
        {
            if (!request.Headers.TryGetValue("Authorization", out var token))
            {
                return null; 
            }
            return token;
        }

    }

}