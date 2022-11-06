# UID2 Client for .NET

See `src/SampleApp/Program.cs` for example usage.

## Build

The library uses .NET Standard 2.1. Unit tests and sample app use .NET 5.0.

```
dotnet build
dotnet test
```

To run the sample app:

```
dotnet run --project src/SampleApp/SampleApp.csproj https://integ.uidapi.com \
	<your-api-token> <your-secret-key> <advertising-token>
```
