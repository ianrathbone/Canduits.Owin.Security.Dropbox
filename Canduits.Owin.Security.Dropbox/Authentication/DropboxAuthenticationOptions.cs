using System;
using System.Collections.Generic;
using System.Net.Http;
using Canduits.Owin.Security.Dropbox.Authentication.Provider;
using Microsoft.Owin.Security;

namespace Canduits.Owin.Security.Dropbox.Authentication
{
    public class DropboxAuthenticationOptions : AuthenticationOptions
    {
        public const string Scheme = "Dropbox";

        public DropboxAuthenticationOptions()
            : base(Scheme)
        {
            Caption = Scheme;
            ReturnEndpointPath = "/signin-dropbox";
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Scope = new List<string>();
        }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string ReturnEndpointPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IDropboxAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public IList<string> Scope { get; private set; }
    }
}