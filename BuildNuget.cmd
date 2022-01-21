del src\UID2.Client\bin\Release\*.nupkg
dotnet build UID2.Client.sln --configuration=Release
dotnet pack -p:NuspecFile=..\..\UID2.Client.nuspec --configuration Release
pause
