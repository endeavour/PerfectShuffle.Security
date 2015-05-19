// include Fake lib
#r "packages/FAKE/tools/FakeLib.dll"
open Fake
open Fake.AssemblyInfoFile
open Fake.FileSystemHelper

RestorePackages()

let buildVersion = "0.1.2"

// Properties
let buildDir = "./build/"
let testDir  = "./test/"

let packagingDir = "./build/packages/"
let packagingRoot = "./build/packages/nuget/"
let allPackageFiles =
  [|
    buildDir + "PerfectShuffle.Security.dll"
    "license.txt"
  |]
  
let projectName = "PerfectShuffle.Security"
let authors = ["James Freiwirth"]
let projectDescription = "Helper library security-related functionality. Includes a basic JWT implementation, OAuth authentication and password hashing functions"
let projectSummary = "Security helper library"
let nuspecFile = "PerfectShuffle.Security/PerfectShuffle.Security.nuspec"

// Targets
Target "Clean" (fun _ ->
    CleanDir buildDir
)

Target "BuildApp" (fun _ ->
    CreateFSharpAssemblyInfo "./PerfectShuffle.Security/AssemblyInfo.fs"
        [Attribute.Title "PerfectShuffle.Security"
         Attribute.Description "Authentication and JWT tools"
         Attribute.Guid "34e4036c-e16c-4cc4-84d3-820207ec5837"
         Attribute.Product "PerfectShuffle.Security"
         Attribute.Version buildVersion
         Attribute.FileVersion buildVersion]

    !! "PerfectShuffle.Security/*.fsproj"
      |> MSBuildRelease buildDir "Build"
      |> Log "AppBuild-Output: "
)

Target "BuildTest" (fun _ ->
    !! "PerfectShuffle.Security.Tests/*.fsproj"
      |> MSBuildDebug testDir "Build"
      |> Log "TestBuild-Output: "
)

Target "Test" (fun _ ->
    !! (testDir + "/PerfectShuffle.Security.Tests.dll")
      |> NUnit (fun p ->
          {p with
             DisableShadowCopy = true;
             OutputFile = testDir + "TestResults.xml" })
)

Target "CreatePackage" (fun _ ->
    // Copy all the package files into a package folder
    CopyFiles packagingDir allPackageFiles

    ensureDirExists (System.IO.DirectoryInfo(packagingRoot))
    NuGet (fun p -> 
        {p with
            Authors = authors
            Project = projectName
            Description = projectDescription                               
            OutputPath = packagingRoot
            Summary = projectSummary
            WorkingDir = packagingDir
            Version = buildVersion
            //AccessKey = myAccesskey
            Publish = false
            Files =
              [
                "license.txt", None, None
                "*.dll", Some("lib"), None
              ]
            Dependencies =
              [
                "FSharp.Data", "2.2.2"
              ]}) 
            nuspecFile
)

Target "Default" (fun _ ->
    ()
)

// Dependencies
"Clean"
  ==> "BuildApp"
  ==> "BuildTest"
  ==> "Test"
  ==> "CreatePackage"
  ==> "Default"

// start build
RunTargetOrDefault "Default"