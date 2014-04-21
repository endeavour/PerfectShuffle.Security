namespace PerfectShuffle.OAuth

module JWT =

  open System
  open System.Collections.Generic
  open System.Security.Cryptography
  open System.Text

  type JwtHashAlgorithm =
  | RS256
  | HS256
  | HS384
  | HS512
    with

    static member FromString (algorithmName:string) =
      match algorithmName with
      | "RS256" -> RS256
      | "HS256" -> HS256
      | "HS384" -> HS384
      | "HS512" -> HS512
      | _ -> invalidArg "name" "Unsupported algorithm"

    override this.ToString() =
      match this with
      | RS256 -> "RS256"
      | HS256 -> "HS256"
      | HS384 -> "HS384"
      | HS512 -> "HS512"
  
  let hashAlgorithms =
    [
      (RS256, fun key -> new HMACSHA256(key) :> HMAC)
      (HS256, fun key -> new HMACSHA256(key) :> HMAC)
      (HS384, fun key -> new HMACSHA384(key) :> HMAC)
      (HS512, fun key -> new HMACSHA512(key) :> HMAC)
    ] |> Map.ofSeq

  open FSharp.Data

  let private join seperator (strings:seq<string>) = String.Join(seperator, strings)
  let private toByteArray (str:string) = Encoding.UTF8.GetBytes(str)  
  
  let private hash algorithm key (bytes:byte[]) =
    let hasher = hashAlgorithms.[algorithm](key)
    hasher.ComputeHash(bytes)

  let private urlEncode bytes =
    Convert
      .ToBase64String(bytes)
      .Split('=').[0]
      .Replace('+', '-')
      .Replace('/', '_')

  let private urlDecode (str:string) =
    let newStr = str.Replace('-', '+').Replace('_', '/')
    let newStr =
      match newStr.Length % 4 with
      | 0 -> newStr
      | 1 -> newStr + "==="
      | 2 -> newStr + "=="
      | 3 -> newStr + "="
      | _ -> failwith "Assertion failure"

    Convert.FromBase64String(newStr)

  let encode (key:byte[]) (algorithm:JwtHashAlgorithm) (payload:JsonValue) =
    let header =
      [|
        ("alg", JsonValue.String (string algorithm))
        ("typ", JsonValue.String "JWT")        
      |]
      |> JsonValue.Record
    
    let segments =
      [header;payload]
      |> List.map string
      |> List.map toByteArray
      |> List.map urlEncode      

    let signature =
      segments
      |> join "."
      |> toByteArray
      |> hash algorithm key
      |> urlEncode

    let signedToken = segments @ [signature]

    let json = signedToken |> join "."
    
    json

  let private split char (str:string) = str.Split(char)
  let private toUtf8 (bytes:byte[]) = Encoding.UTF8.GetString(bytes)
    
  type Token(token) =
    let parts = token |> split [|'.'|]
    
    let header, payload, signature =
      match parts with
      | [|a;b;c|] -> a,b,c
      | _ -> raise <| System.ArgumentException("Token does not have correct number of parts")
    
    let toJson urlEncodedString =
      urlEncodedString
      |> urlDecode
      |> toUtf8
      |> JsonValue.Parse

    let headerJson, payloadJson = toJson header, toJson payload
    let headerData =
      headerJson
      |> function JsonValue.Record x -> x | _ -> raise <| System.ArgumentException("Token header not in valid format")
      |> Map.ofSeq

    let payloadData =
      printfn "%A" payloadJson
      payloadJson
      |> function JsonValue.Record x -> x | _ -> raise <| System.ArgumentException("Token payload not in valid format")
      |> Map.ofSeq

    let verify (key:byte[]) =
      match headerData.TryFind("alg") with
      | Some(JsonValue.String alg) ->
        try
          let algorithm = JwtHashAlgorithm.FromString(alg)
          let actualSignature =
            [header; payload]
            |> join "."
            |> toByteArray
            |> hash algorithm key
            |> urlEncode
          signature = actualSignature
        with ex ->
          false
      | _ -> false
      
    with
      member __.Header = headerData
      member __.Payload = payloadData
      member __.Verify(sharedKey) = verify sharedKey

  let decode token = Token(token).Payload
