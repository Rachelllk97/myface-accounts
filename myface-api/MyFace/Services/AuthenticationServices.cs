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
        public bool IsUserAuthenticated(string credentials, IUsersRepo _users)
        {

            var encoding = Encoding.GetEncoding("iso-8859-1");
            credentials = encoding.GetString(Convert.FromBase64String(credentials));

            int separator = credentials.IndexOf(':');
            string userName = credentials.Substring(0, separator);
            string password = credentials.Substring(separator + 1);
            var user = _users.GetByUserName(userName);
            var salt = user.Salt;

            var hashGenerator = new HashGenerator();
            var hashedPassword = hashGenerator.GenerateHash(password, salt);

            return user.HashedPassword == hashedPassword;

        }

    }

}