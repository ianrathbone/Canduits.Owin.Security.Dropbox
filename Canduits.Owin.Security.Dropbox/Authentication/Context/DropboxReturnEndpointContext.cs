using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Canduits.Owin.Security.Dropbox.Authentication.Context
{
    public class DropboxReturnEndpointContext : ReturnEndpointContext
    {
        public DropboxReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket,
            IDictionary<string, string> errorDetails)
            : base(context, ticket, errorDetails)
        {
        }
    }
}