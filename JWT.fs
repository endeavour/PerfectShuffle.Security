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

  open FSharp.Data.Json

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

  let encode (payload:JsonValue) (key:byte[]) (algorithm:JwtHashAlgorithm) =
    let header =
      [
        ("alg", JsonValue.String (string algorithm))
        ("typ", JsonValue.String "JWT")        
      ]
      |> Map.ofSeq
      |> JsonValue.Object
    
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
    let headerData = headerJson |> function JsonValue.Object x -> x | _ -> raise <| System.ArgumentException("Token header not in valid format")
    let payloadData = payloadJson |> function JsonValue.Object x -> x | _ -> raise <| System.ArgumentException("Token payload not in valid format")

    with
      member __.Header = headerData
      member __.Payload = payloadData

  let decode token = Token(token).Payload
