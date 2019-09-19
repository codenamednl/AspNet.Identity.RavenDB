using System;
using System.Security.Claims;
using Raven.Imports.Newtonsoft.Json;

namespace AspNet.Identity.RavenDB.Entities
{
    public class RavenUserClaim
    {
        public RavenUserClaim(Claim claim)
        {
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }

        [JsonConstructor]
        public RavenUserClaim(string claimType, string claimValue)
        {
            ClaimType = claimType ?? throw new ArgumentNullException(nameof(claimType));
            ClaimValue = claimValue ?? throw new ArgumentNullException(nameof(claimValue));
        }

        public string ClaimType { get; }
        public string ClaimValue { get; }
    }
}