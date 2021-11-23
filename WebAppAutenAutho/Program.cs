using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

#region ConfigureServices
// Add services to the container.
builder.Services.AddControllersWithViews();


Action<CookieAuthenticationOptions> configureOptions = Whatever;

void Whatever(CookieAuthenticationOptions options)
{
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/denied";
    options.Events = new CookieAuthenticationEvents()
    {
        OnSigningIn = async context =>
        {
            var principal = context.Principal;
            if (principal.HasClaim(c => c.Type == ClaimTypes.NameIdentifier))
            {
                if (principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value == "bob")
                {
                    var claimsIdentity = principal.Identity as ClaimsIdentity;
                    claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                }
            }
            await Task.CompletedTask;
        },
        OnSignedIn = async context =>
        {
            await Task.CompletedTask;
        },
        OnValidatePrincipal = async context =>
        {
            await Task.CompletedTask;
        },
    };
}

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(configureOptions);

#endregion

var app = builder.Build();

#region Middleware (Configure)
// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
#endregion

