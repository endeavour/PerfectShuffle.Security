namespace PerfectShuffle.Authentication

module Convert =  
  open System.Numerics
  let charlist = "0123456789abcdefghijklmnopqrstuvwxyz"
  let base' = BigInteger(36)

  let ToBase36String (input:byte[]) =
    // Append a zero to make sure the resulting integer is positive
    let input = Array.append input [|0uy|]
    let mutable num = BigInteger(input)
    let mutable output = []
    while (not num.IsZero) do
      let index = int (num % base')
      output <- charlist.[index]::output
      num <- BigInteger.Divide(num, base')
    new System.String (List.toArray output)

module TokenGeneration =
  open System
  open System.Security.Cryptography
  let rng = new RNGCryptoServiceProvider()

  let createRandomBase64Token numBytes =
    let buffer = Array.zeroCreate numBytes
    rng.GetBytes(buffer)
    let token = Convert.ToBase64String buffer        
    token.TrimEnd([|'='|]) // Remove trailing equal signs, they look awful.

  let createRandomBase36Token numBytes =
    let buffer = Array.zeroCreate numBytes
    rng.GetBytes(buffer)
    let token = Convert.ToBase36String buffer        
    token

/// Utilities for password hashing and salting
/// For security, every time a password is created or changed a new salt should be applied!
/// See: https://crackstation.net/hashing-security.htm
module PasswordHashing =
  
  open System
  open System.Security.Cryptography
  let rng = new RNGCryptoServiceProvider()  

  let createRandomSalt numBytes =
    TokenGeneration.createRandomBase64Token numBytes

  let hashPasswordWithSalt (password:string) (salt:string) =
     let saltBytes = System.Text.Encoding.UTF8.GetBytes(salt)
     let hashBytes = new System.Security.Cryptography.Rfc2898DeriveBytes(password, saltBytes)     
     let hashBytes = hashBytes.GetBytes(256/8)
     let hash = Convert.ToBase64String(hashBytes)
     hash

  type PasswordHash =
    {PasswordHash : string; PasswordSalt : string}

  let hashPassword password =
    let saltLength = 64 //bytes
    let salt = createRandomSalt saltLength
    let hashedPassword = hashPasswordWithSalt password salt
    {PasswordHash = hashedPassword; PasswordSalt = salt}