namespace PerfectShuffle.Authentication

module OAuth =

  module Google =
  
    let nonceCache = new System.Runtime.Caching.MemoryCache("OAuthState")
  
    /// Time to wait for Google to respond before we clear the nonce from the cache
    let timeout = System.TimeSpan.FromMinutes(2.)

    /// <summary>
    /// Make a request for a code. The state is a nonce that the server will include when it
    /// makes the request back to us.
    /// </summary>
    /// <param name="state">
    /// An opaque string that is round-tripped in the protocol.
    /// Provides protection against attacks such as cross-site request forgery.
    /// </param>
    /// <param name="clientId">
    /// The client ID that you obtain when you register your app at the Google Cloud Console.
    /// </param>
    /// <param name="redirectUri">
    /// The URI that you specify when you register your app at the Google Cloud Console.
    /// </param>
    /// <param name="additionalScope">
    /// Any additional scope required (openid, profile, email) included by default
    /// </param>
    let createRequestUri state clientId redirectUri additionalScope =
      let boolStr x = if x then "true" else "false"
      let join seperator (strings:seq<string>) = System.String.Join(seperator, strings)
        
      let response_type = "code"
      let scope =
        ["openid"; "profile"; "email"] @ additionalScope
        |> join " "

      let prompt = "consent"
      let access_type = "offline"
      let include_granted_scopes = true

      let uristr =
        "https://accounts.google.com/o/oauth2/auth"
        + "?client_id=" + clientId
        + "&response_type=" + response_type
        + "&scope=" + scope
        + "&redirect_uri=" + redirectUri
        + "&state=" + state
        + "&access_type=" + access_type
        + "&include_granted_scopes=" + (boolStr include_granted_scopes)

      nonceCache.Add(state, System.String.Empty, System.DateTimeOffset.Now.Add(timeout)) |> ignore<bool>

      let uri = System.Uri(uristr)
      uri
        
    open FSharp.Data
    open FSharp.Data.JsonExtensions

    /// OAuth token response
    type TokenResponse =
      {
        /// A token that can be sent to a Google API.
        AccessToken:string
        /// A JWT that contains identity information about the user that is digitally signed by Google.
        IdToken:string
        /// The remaining lifetime of the access token (seconds)
        ExpiresIn:int
        /// Identifies the type of token returned. At this time, this field always has the value Bearer.
        TokenType:string
        ///  A refresh token provides your app continuous access to Google APIs while the user is not logged into your application.
        /// This field is only present if access_type=offline is included in the authentication request.
        RefreshToken:string option
      }

    let grantType = "authorization_code" // Hard-coded value as defined in the OAuth 2.0 specification.

    /// Exchanges an authorization code for an access token and (optionally) a refresh token
    let exchangeCodeForTokens clientId clientSecret redirectUri code =

      let data = 
        [
          ("code",code)
          ("client_id", clientId)
          ("client_secret", clientSecret)
          ("redirect_uri", redirectUri)
          ("grant_type", grantType)
        ]

      let requestBody = FSharp.Data.HttpRequestBody.FormValues data
    
      let req =
        Http.AsyncRequest
          ("https://accounts.google.com/o/oauth2/token",
            body = requestBody)

      async {
      let! response = req
      let json =
        match response.Body with
        | HttpResponseBody.Text json -> json
        | HttpResponseBody.Binary _ -> raise <| System.Web.HttpParseException("Unexpected binary response")
    
      let json = FSharp.Data.JsonValue.Parse(json)
    
      let accessToken = json?access_token
      let idToken = json?id_token
      let expiresIn = json?expires_in
      let tokenType = json?token_type
      let refreshToken =
        json.TryGetProperty "refresh_token"
        |> Option.map (fun x -> x.AsString())

      return {
        AccessToken = accessToken.AsString()
        IdToken = idToken.AsString()
        ExpiresIn = expiresIn.AsInteger()
        TokenType = tokenType.AsString()
        RefreshToken = refreshToken }
      }

    type RefreshTokenResponse = {AccessToken:string; ExpiresIn:int; TokenType:string}
  
    /// Obtains a new access token given a refresh token (assuming the access hasn't been revoked by the user)
    let exchangeRefreshTokenForAccessToken refreshToken clientId clientSecret=
      let data = 
        [
          ("refresh_token", refreshToken)
          ("client_id", clientId)
          ("client_secret", clientSecret)
          ("grant_type", grantType)
        ]

      let requestBody = FSharp.Data.HttpRequestBody.FormValues data
    
      let req =
        Http.AsyncRequest
          ("https://accounts.google.com/o/oauth2/token",
            body = requestBody)

      async {
      let! response = req
      let json =
        match response.Body with
        | HttpResponseBody.Text json -> json
        | HttpResponseBody.Binary _ -> raise <| System.Web.HttpParseException("Unexpected binary response")
    
      let json = FSharp.Data.JsonValue.Parse(json)
    
      let accessToken = json?access_token
      let expiresIn = json?expires_in
      let tokenType = json?token_type
    
      let token : RefreshTokenResponse =
        {
          AccessToken = accessToken.AsString()
          ExpiresIn = expiresIn.AsInteger()
          TokenType = tokenType.AsString()
        }
      return token
      }
       
    type Authorization =
      {
        /// An opaque string that is round-tripped in the protocol.
        /// Provides protection against attacks such as cross-site request forgery.
        State : string;
        /// One-time authorization code that your server can exchange for an access token and ID token
        Code : string
      }
        
    /// Parses a query string and returns the state and the authorization code
    let authorizationFromQueryString (uri:System.Uri) =
      let charsToStr chars = System.String(Seq.toArray chars)
    
      let queryString =
        uri.AbsoluteUri
        |> Seq.skipWhile ((<>) '?')
        |> Seq.skip 1
        |> charsToStr      

      let queryParams = System.Web.HttpUtility.ParseQueryString(queryString)
    
      {State = queryParams.["state"]; Code = queryParams.["code"]}
