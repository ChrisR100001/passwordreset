using System.Diagnostics;
using System.Runtime.InteropServices;

var builder = WebApplication.CreateBuilder(args);

//Create our event source in the event log
if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    if (!EventLog.SourceExists("PasswordResetPortal"))
        EventLog.CreateEventSource("PasswordResetPortal", "PasswordResetPortal");
}

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.Secure = CookieSecurePolicy.Always;
});
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        var headers = ctx.Context.Response.Headers;

        headers["X-Content-Type-Options"] = "nosniff";
        headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "media-src 'none'; " +
            "manifest-src 'none'; " +
            "object-src 'none'; " +
            "frame-src 'none'; " +
            "worker-src 'self'; " +
            "child-src 'none'; " +
            "form-action 'self'; " +
            "navigate-to 'self'; " +
            "base-uri 'self'; " +
            "frame-ancestors 'none';";

        headers["Referrer-Policy"] = "no-referrer";
        headers["X-Frame-Options"] = "DENY";
        headers["Permissions-Policy"] = "geolocation=(), microphone=()";
    }
});

app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] =
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "script-src 'self' 'unsafe-inline';" +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data:; " +
        "connect-src 'self'; " +
        "media-src 'none'; " +
        "manifest-src 'none'; " +
        "object-src 'none'; " +
        "frame-src 'none'; "+
        "worker-src 'self'; " +
        "child-src 'none'; " +
        "form-action 'self'; " +
        "navigate-to 'self'; " +
        //"prefetch-src 'none'; " +
        //"sandbox allow-scripts allow-forms; ";// +
        "base-uri 'self'; " +
        "frame-ancestors 'none';";


    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "geolocation=(), microphone=()";

    await next();
});

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();
app.UseCookiePolicy();


app.Run();
