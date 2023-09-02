using JwtStore;
using JwtStore.Models;
using JwtStore.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddTransient<JwtService>();
//Adicionando autenticação na API. Se muder ordem não funciona. São middlewares
builder.Services.AddAuthentication(configureOptions:X =>
{
    X.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    X.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(X => 
{
    X.TokenValidationParameters = new TokenValidationParameters
    {
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.PrivateKey)),
        ValidateIssuer = false,
        ValidateAudience = false
    };
}) ; 

builder.Services.AddAuthorization(x =>
{
    x.AddPolicy("PremiumPolicy", p => p.RequireRole("Premium")); //Para authorizar a política tem que ser premium, compara variável do token com essa passada
}); //Vai pedir o header the token

var app = builder.Build();

app.UseAuthentication(); //Utilizando os middle wares adicionados acima
app.UseAuthorization();

app.MapGet("/", handler:(JwtService service)
    => service.Create(new User( Id:1,
    Name:"Rafael",
    Email:"teste@eu.com",
    Image:"imagem",
    Password: "1234",
    Roles:new[]
    {
        "Student",
        "Premium"
    })));

app.MapGet("/restrito", handler: (ClaimsPrincipal user)
    => $"Autenticou com usuário: {user.Identity.Name}")
    .RequireAuthorization();

app.MapGet("/premium", handler: (ClaimsPrincipal user)
    => $"Autenticou com usuário: {user.Identity.Name}")
    .RequireAuthorization("PremiumPolicy");

app.Run();
