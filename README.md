# jwt-authentication-in-dotnet-5
JWT Authentication for .NET 5 REST APIs (Bearer Token)

`dotnet new webapi -o .`

`dotnet new sln -o . -n JWT`

`dotnet sln add .\jwt-authentication-in-dotnet-5.csproj`

`import Nuget Package called Microsoft.IdentityModel.Tokens`

`import Nuget Package called System.IdentityModel.Tokens.Jwt`

Add field to "Headers"

Authorization: Bearer <token>

