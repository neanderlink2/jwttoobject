using JwtToObject.Core.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

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
