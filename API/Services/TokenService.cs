using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services;

public class TokenService(IConfiguration config) : ITokenService
{
    public string CreateToken(AppUser user)
    {
        var tokenKey = config["TokenKey"] ?? throw new InvalidOperationException("TokenKey is not configured.");
        if (tokenKey.Length < 64)
        {
            throw new InvalidOperationException("TokenKey must be at least 32 characters long.");
        }
        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(tokenKey));

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.UserName),
        };

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddDays(7),
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        
        return tokenHandler.WriteToken(token);
            
    } 
}
