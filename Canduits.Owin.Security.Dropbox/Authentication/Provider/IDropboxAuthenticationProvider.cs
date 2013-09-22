using System.Threading.Tasks;
using Canduits.Owin.Security.Dropbox.Authentication.Context;

namespace Canduits.Owin.Security.Dropbox.Authentication.Provider
{
    public interface IDropboxAuthenticationProvider
    {
        Task Authenticated(DropboxAuthenticatedContext context);
        Task ReturnEndpoint(DropboxReturnEndpointContext context);
    }
}