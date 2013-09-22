using System;
using Canduits.Owin.Security.Dropbox.Authentication;
using Microsoft.Owin.Security;

namespace Owin
{
    public static class Extension
    {
        public static IAppBuilder UseDropboxAuthentication(
            this IAppBuilder app,
            DropboxAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof (DropboxAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseDropboxAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseDropboxAuthentication(
                app,
                new DropboxAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType(),
                });
        }
    }
}