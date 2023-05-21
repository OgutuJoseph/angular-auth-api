# Project Resources

## Notes
- db context can be saved in any prefered directory: Context(like in this case), Data(like in auth crud) etc etc; with a prefered filename
- : DbContext imported from -- Microsoft.EntityFrameworkCore

## Configuring Service on Program.cs

- > builder.Services.AddDbContext<AppDbContext>(option =>
{
    option.UseSqlServer(builder.Configuration.GetConnectionString("SqlServerConnStr"));
});

## Running Up Db

- add-migration (migration name)
- update-database
- "Trust Server Certificate = True;" MUST be included in the appsettings.json, connectionstrings

## Allow Cors (option 1)

- Go to Promram.cs
- Add Below
builder.Services.AddCors(option =>
{
    option.AddPolicy("MyPolicy", builder =>
    {
        builder
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

- Then below (above useAuthorization)
- Add the line below
- > app.UseCors("MyPolicy")
- > app.UseAuthentication() (optionally)

## Allow Cors (option 2)

- Still on Program.cs, above useAuthorization
- Add line below 
- > app.UseCors(policy => policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin());

## Installed Packages
- Microsoft.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.AspNetCore.Authentication.JwtBearer (For JWT Token, Confirm compatible version with net core)
- Microsoft.EntityFrameworkCore.Tools