using JwtToObject.Core.Models;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtToObject.Core
{
    public class JwtConverter
    {
        public static JwtModel ConvertToModel(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(token) as JwtSecurityToken;

            return new JwtModel(
                    GetClaimValue(jsonToken, "nameid"),
                    GetClaimValue(jsonToken, "unique_name"),
                    GetClaimValue(jsonToken, "email"),
                    GetClaimValue(jsonToken, ClaimTypes.MobilePhone),
                    GetClaimValue(jsonToken, "role"),
                    ToDateTimeFromEpoch(jsonToken.Payload.Nbf.Value),
                    ToDateTimeFromEpoch(jsonToken.Payload.Exp.Value),
                    ToDateTimeFromEpoch(jsonToken.Payload.Iat.Value)
                );
        }

        public static async Task<string> GetCreditCardToken(string cardNumber, string expirationYear, string expirationMonth, string verificationCode)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = await Task.Run(() =>
            {
                var secret = Encoding.ASCII.GetBytes("F0egMy4j6jJ8yOCwM5jUrMGf0gIFgH5D1Tzu2thbn8JyXdLSv4TBXV53ACHdwauCKClQA8dPvKy8JOO8szUjKh9P06kUucTV_E1SHB4Sgt886Zb3CbTY4OYOOVm7NVSDYvfFAP2zm8zlseAz5vVsDUuURK7hdXdrccGk02YJRynUN02zgoY6lOfsn9s-KUl8U0WoooPRdffLCqRuGF_1le4wewu6vp2qAmW_o0_BKc4M70Ub1OqbHt1EGe-OnsCWYlt-g8biPuFHq2D5M_JStyVK94f9c4aQgkNi3A-uqQyWE7JlmLqpB6PA2d0wPjKCshsPz6fTFr9wf6AXNaLCIQ");

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim("card_number", cardNumber),
                        new Claim("exp_year", expirationYear),
                        new Claim("exp_month", expirationMonth),
                        new Claim("cvc", verificationCode),
                    }),
                    Expires = DateTime.UtcNow.AddDays(7),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256Signature)
                };
                return tokenHandler.CreateToken(tokenDescriptor);
            });

            return tokenHandler.WriteToken(token);
        }

        private static string GetClaimValue(JwtSecurityToken token, string type)
        {
            return token.Claims.FirstOrDefault(x => x.Type == type)?.Value;
        }

        private static DateTime ToDateTimeFromEpoch(long intDate)
        {
            var timeInTicks = intDate * TimeSpan.TicksPerSecond;
            return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddTicks(timeInTicks);
        }
    }
}
