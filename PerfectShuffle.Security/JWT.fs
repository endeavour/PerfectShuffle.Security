namespace PerfectShuffle.Security

module JWT =
  
  open System
  open System.IdentityModel.Tokens
  open System.Security.Claims
  open System.Security.Cryptography

  type SigningKey =
  | HS256 of symmetricKey:byte[]
  | RS256 of key:RSAParameters

  let jwtHandler = System.IdentityModel.Tokens.JwtSecurityTokenHandler()
  
  let createRandomSymmetricKey() =
    let rng = new System.Security.Cryptography.RNGCryptoServiceProvider()
    
    let bytes : byte[] = Array.zeroCreate (256 / 8) // 256 bit key
    rng.GetBytes(bytes)
    bytes

  let base64UrlEncode bytes =
    Convert
      .ToBase64String(bytes)
      .Split('=').[0]
      .Replace('+', '-')
      .Replace('/', '_')

  let base64UrlDecode (str:string) =
    let newStr = str.Replace('-', '+').Replace('_', '/')
    let newStr =
      match newStr.Length % 4 with
      | 0 -> newStr
      | 1 -> newStr + "==="
      | 2 -> newStr + "=="
      | 3 -> newStr + "="
      | _ -> failwith "Assertion failure"
    Convert.FromBase64String(newStr)

  let generateJwtToken (signingKey:SigningKey) (tokenIssuerName:string) (audience:string) (validity:System.IdentityModel.Protocols.WSTrust.Lifetime) (claims:seq<Claim>) =
    use publicAndPrivate = new RSACryptoServiceProvider()

    let signingCredentials =
      match signingKey with
      | HS256 symmetricKey ->
        if symmetricKey.Length <> 256 / 8 then
          invalidArg "symmetricKey" "Symmetric key must be exactly 256 bits"
        SigningCredentials(InMemorySymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest)
      | RS256 key ->
        
        publicAndPrivate.ImportParameters key
        SigningCredentials(RsaSecurityKey(publicAndPrivate), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest)

    let now = System.DateTime.UtcNow

    let tokenDescriptor =
      SecurityTokenDescriptor(
        Subject = ClaimsIdentity(claims),
        TokenIssuerName = tokenIssuerName,
        AppliesToAddress = audience,
        Lifetime = validity,
        SigningCredentials = signingCredentials
        )

    let token = jwtHandler.CreateToken(tokenDescriptor)

    token :?> JwtSecurityToken

  let exportPublicKey (rsaParams:RSAParameters) =
    let r = System.Security.Cryptography.RSA.Create()
    r.ImportParameters rsaParams
    use ms = new System.IO.MemoryStream()
    use sw = new System.IO.StreamWriter(ms)
    let bcRsa = Org.BouncyCastle.Security.DotNetUtilities.GetRsaPublicKey(r)
    Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(bcRsa)
    sw.Flush()
    ms.ToArray() |> System.Text.Encoding.UTF8.GetString

  let exportPrivateKey (rsaParams:RSAParameters) =
    let r = System.Security.Cryptography.RSA.Create()
    r.ImportParameters rsaParams
    use ms = new System.IO.MemoryStream()
    use sw = new System.IO.StreamWriter(ms)
    let bcRsa = Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(r)
    Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(bcRsa.Private)
    sw.Flush()
    ms.ToArray() |> System.Text.Encoding.UTF8.GetString

  let rsaToXml (rsaParams:RSAParameters) =
    let rsa = System.Security.Cryptography.RSA.Create()
    rsa.ImportParameters rsaParams
    rsa.ToXmlString(true)

  let rsaFromXml (rsaXml:string) : RSAParameters =
    let rsa = System.Security.Cryptography.RSA.Create()
    rsa.FromXmlString(rsaXml)
    rsa.ExportParameters true

  let validateToken (key:SigningKey) (tokenIssuerName:string) (audience:string) (token:string) =
    let decodedToken = jwtHandler.ReadToken(token) :?> JwtSecurityToken
    
    let lifetimeValidityChecker = LifetimeValidator(fun notBefore expires token validationParameters ->
      match Option.ofNullable notBefore, Option.ofNullable expires with
      | None, None -> true
      | Some(notBefore), None -> notBefore <= DateTime.UtcNow
      | None, Some(expires) -> DateTime.UtcNow <= expires
      | Some(notBefore), Some(expires) -> notBefore <= DateTime.UtcNow && DateTime.UtcNow <= expires      
      )

    let validationParams =
      match key with
      | HS256 symmetricKey ->
        if decodedToken.SignatureAlgorithm <> System.IdentityModel.Tokens.JwtAlgorithms.HMAC_SHA256 then failwith "Key and token must have matching signature types"
        TokenValidationParameters(
          ValidAudience = audience,
          IssuerSigningToken = System.ServiceModel.Security.Tokens.BinarySecretSecurityToken(symmetricKey),
          ValidIssuer = tokenIssuerName,
          ValidateLifetime = true,
          LifetimeValidator = lifetimeValidityChecker)
      | RS256 key ->
        if decodedToken.SignatureAlgorithm <> System.IdentityModel.Tokens.JwtAlgorithms.RSA_SHA256 then failwith "Key and token must have matching signature types"
        let r = System.Security.Cryptography.RSA.Create()
        r.ImportParameters key
        let key = System.IdentityModel.Tokens.RsaSecurityToken(r).SecurityKeys.[0]
        TokenValidationParameters(
          ValidAudience = audience,
          IssuerSigningKey = key,
          ValidIssuer = tokenIssuerName,
          ValidateLifetime = true,
          LifetimeValidator = lifetimeValidityChecker
          ) 
    
    let claims, token = jwtHandler.ValidateToken(token, validationParams)
    claims, token
