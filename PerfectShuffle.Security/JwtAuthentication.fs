namespace PerfectShuffle.Security

module JwtAuthentication = 
  open PerfectShuffle.Security
  open System

  [<AutoOpen>]
  module private Maybe =

    type SafeMaybeBuilder() =
      member this.Delay f = try f() with ex -> None
      member this.Return (x) = Some(x)
      member this.Bind (x, f) =
        match x with
        | Some(value) ->
          try
            f value
          with ex ->
            None
        | None -> None
    
    let safely(f : unit -> 'a) = fun () -> try Some(f()) with ex -> None
    let safelyRun(f : unit -> 'a) = (safely f)()

  exception SecurityTokenExpiredException

  let private unixEpoch = System.DateTime(1970,1,1)

  /// Returns a ClaimsPrincipal for the given token. Throws an exception if it doesn't validate (signature doesn't match, past expiry etc)
  let validate (log:string -> unit) (hashAlgorithm:JWT.JwtHashAlgorithm) (signingKey:byte[]) (tokenString:string) =
    log "Authorization header: bearer string found"
    let token = PerfectShuffle.Security.JWT.Token(tokenString)

    if not <| token.Verify(hashAlgorithm, signingKey) then
      raise <| System.IdentityModel.Tokens.SecurityTokenValidationException()   
                                                     
    log "Successfully decoded JWT token"
   
    let claims =
      token.Payload
      |> Map.toSeq
      |> Seq.choose (fun (k,v) ->
        match v with
        | FSharp.Data.JsonValue.String(s) -> Some(k,s)
        | _ -> None)
      |> Seq.map (fun (k,v) -> k, System.Security.Claims.Claim(k, v, String.Empty))
      |> Map.ofSeq

    match claims.TryFind "exp" with
    | None -> log "Security token expiration check passed (no expiration found)"
    | Some(expiry) ->
      match Double.TryParse expiry.Value with
      | true, secondsSinceEpoch when DateTime.UtcNow <= unixEpoch.AddSeconds(secondsSinceEpoch) ->
        log "Security token expiration check passed (within validity period)"
      | _ ->
        log "Security token expired"
        raise <| SecurityTokenExpiredException

    match claims.TryFind "nbf" with
    | None -> log "Security token validfrom check passed (no validfrom found)"
    | Some(expiry) ->
      match Double.TryParse expiry.Value with
      | true, secondsSinceEpoch when DateTime.UtcNow >= unixEpoch.AddSeconds(secondsSinceEpoch) ->
        log "Security token validfrom check passed (within validity period)"
      | _ ->
        log "Security token not yet valid"
        raise <| SecurityTokenExpiredException

    let claims = claims |> Map.toSeq |> Seq.map snd

    let identity = System.Security.Claims.ClaimsIdentity(claims)
    let claimsPrincipal = System.Security.Claims.ClaimsPrincipal(identity)
    claimsPrincipal

  // http://stackoverflow.com/questions/14735753/how-to-configure-microsoft-jwt-with-symmetric-key
  let encode (signingKey:byte[]) (expiry:System.DateTime) (claims:seq<System.Security.Claims.Claim>) = 
    let expiryValue =
      let timespan = expiry - unixEpoch
      int64 timespan.TotalSeconds

    let claims =
      seq {
        yield! claims
        yield System.Security.Claims.Claim("exp", string expiryValue)
      }

    JWT.encodeClaims signingKey PerfectShuffle.Security.JWT.HS256 claims

  let private safemaybe = new SafeMaybeBuilder()

  let tryValidate (log:string -> unit) (hashAlgorithm:JWT.JwtHashAlgorithm) (signingKey:byte[]) (jwtToken:string) = 
    safemaybe {
      let! claims = safelyRun (fun() -> validate log hashAlgorithm signingKey jwtToken)
      return claims
    }         
  