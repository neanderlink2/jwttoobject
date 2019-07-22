using System;

namespace JwtToObject.Core.Models
{
    public class JwtModel
    {
        public JwtModel(string nameIdentifier, string name, string email, string mobilePhone, string role, 
            DateTime notValidBefore, DateTime expiration, DateTime issuedAt)
        {
            NameIdentifier = nameIdentifier;
            Name = name;
            Email = email;
            MobilePhone = mobilePhone;
            Role = role;
            NotValidBefore = notValidBefore;
            Expiration = expiration;
            IssuedAt = issuedAt;
        }

        public string NameIdentifier { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string MobilePhone { get; set; }
        public string Role { get; set; }
        public DateTime NotValidBefore { get; set; }
        public DateTime Expiration { get; set; }
        public DateTime IssuedAt { get; set; }
    }
}
