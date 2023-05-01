# UID2 SDK for .NET

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review [the governance rules](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md).

This SDK simplifies integration with UID2 for those using .NET.

## Dependencies

This library uses .NET Standard 2.1. unit tests. The sample app uses .NET 5.0.

## Build

to build, run the following:

```
dotnet build
dotnet test
```

## Run

To run the sample app:

```
dotnet run --project src/SampleApp/SampleApp.csproj https://integ.uidapi.com \
	<your-api-token> <your-secret-key> <advertising-token>
```

## Example Usage

For example usage, see [src/SampleApp/Program.cs](src/SampleApp/Program.cs).