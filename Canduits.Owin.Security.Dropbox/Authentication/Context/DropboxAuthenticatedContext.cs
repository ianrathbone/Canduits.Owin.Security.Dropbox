using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Canduits.Owin.Security.Dropbox.Authentication.Context
{
    public class DropboxAuthenticatedContext : BaseContext
    {
        public DropboxAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            ReferralLink = TryGetValue(user, "referral_link");
            DisplayName = TryGetValue(user, "display_name");
            Uid = TryGetValue(user, "uid");
            Country = TryGetValue(user, "country");
            QuotaInfo = TryGetValue(user, "quota_info");
            Shared = TryGetValue(JObject.Parse(QuotaInfo), "shared");
            Quota = TryGetValue(JObject.Parse(QuotaInfo), "quota");
            Normal = TryGetValue(JObject.Parse(QuotaInfo), "normal");
        }

        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public string ReferralLink { get; private set; }
        public string DisplayName { get; private set; }
        public string Uid { get; private set; }
        public string Country { get; private set; }
        public string QuotaInfo { get; private set; }
        public string Shared { get; private set; }
        public string Quota { get; private set; }
        public string Normal { get; private set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(IDictionary<string, JToken> user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}