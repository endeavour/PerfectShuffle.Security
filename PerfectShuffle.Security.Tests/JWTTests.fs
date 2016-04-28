namespace PerfectShuffle.OAuth.Tests

module JWTTests =

  open NUnit.Framework
  open FsUnit
  open System.Security.Cryptography.X509Certificates
  open FSharp.Data
  open PerfectShuffle.Security.JWT

  [<TestFixture>]
  type Tests() =
   
    [<Test>]
    member __.``Can encode and then verify a JSON Web Token with RS256``() =
      let payload = JsonValue.Record [|"Foo", JsonValue.String "Hello World"|]
      
      let key = System.Text.UTF8Encoding.UTF8.GetBytes("This is a sample key")

      let jwtText = PerfectShuffle.Security.JWT.encode key RS256 payload

      let jwt = PerfectShuffle.Security.JWT.Token(jwtText)

      jwt.Verify(RS256, key) |> should be True

    [<Test>]
    member __.``Trying to manipulate the algorithm fails``() =
      let payload = JsonValue.Record [|"Foo", JsonValue.String "Hello World"|]
      
      let key = System.Text.UTF8Encoding.UTF8.GetBytes("This is a sample key")

      let jwtText = PerfectShuffle.Security.JWT.encode key RS256 payload

      let jwt = PerfectShuffle.Security.JWT.Token(jwtText)

      jwt.Verify(HS256, key) |> should be False
