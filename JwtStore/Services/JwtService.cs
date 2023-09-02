using JwtStore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtStore.Services
{
    public class JwtService
    {
        public string Create(User user)
        {
            var handler = new JwtSecurityTokenHandler();

            var key = Encoding.UTF8.GetBytes(Configuration.PrivateKey); //Essa key deve ficar guardada em um keyvault. Esse config foi só pra funcionar

            var credentials =  new SigningCredentials(key: new SymmetricSecurityKey(key),
                algorithm: SecurityAlgorithms.HmacSha256); //Seleção do algoritmo de encriptação a credencial Isso é a primeira parte de um token JWT (Como se fossem headers) Ver site www.jwt.io para lembrar.

            var tokenDescriptor = new SecurityTokenDescriptor
            {

                Subject = GenerateClaims(user), //
                SigningCredentials = credentials,
                Expires = DateTime.UtcNow.AddHours(2) //Tempo de validade do token
            };

            var token = handler.CreateToken(tokenDescriptor);
            return handler.WriteToken(token);
        }

        private static ClaimsIdentity GenerateClaims(User user)
        {
            var ci = new ClaimsIdentity();

            ci.AddClaim(new Claim(type: "Id", value: user.Id.ToString()));
            ci.AddClaim(new Claim(type: ClaimTypes.Name, value: user.Email));
            ci.AddClaim(new Claim(type: ClaimTypes.Email, value: user.Email));
            ci.AddClaim(new Claim(type: ClaimTypes.GivenName, value: user.Name));
            ci.AddClaim(new Claim(type: "image", value: user.Image));

            foreach (var role in user.Roles)
            {
                ci.AddClaim(new Claim(type: ClaimTypes.Role, value: role));
            }




            return ci;
        }
    } 
}
