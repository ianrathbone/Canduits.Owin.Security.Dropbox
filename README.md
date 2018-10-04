Canduits.Owin.Security.Dropbox
==============================

MVC5 and WebAPI2 middleware OWIN authentication provider for Dropbox.

NOTE: I'm not maintaining this any longer as other people have jumped on the solution and maintained it far better than I have. See solutions like https://github.com/TerribleDev/OwinOAuthProviders

Further information
==============================
This lib is meant to work exactly as the Microsoft owin libraries work for twitter and Facebook. 

In an MVC style project just reference this dll, go to the app start code and use app.UseDropboxAuthentication(key, secret); 
