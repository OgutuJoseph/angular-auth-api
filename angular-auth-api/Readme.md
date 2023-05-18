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

## Installed Packages
- Microsoft.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.AspNetCore.Authentication.JwtBearer (Confirm compatible version with net core)
- Microsoft.EntityFrameworkCore.Tools