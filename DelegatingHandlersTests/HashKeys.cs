using Security.HMACAuthentication.Interfaces;
using System;
using System.Security.Cryptography;

namespace Security.HMACAuthentication
{
    public class HashKeys : IHashKeys
    {
        public string APPId { get; private set; }

        public string ApiKey { get; private set; }

        public string HashAlgorithm { get; private set; }

        public string HmacAlgorithm { get; private set; }

        public string UserId { get; private set; }
        
        public HashKeys(string appId, string apiKey, string hashAlgorithm, string hmacAlgorithm, string userId)
        {
            APPId = appId;
            ApiKey = apiKey;
            HashAlgorithm = hashAlgorithm;
            HmacAlgorithm = hmacAlgorithm;
            UserId = userId;
        }

        static public HashKeys GenerateHashKeys(string userId, string hashAlgorithm, string hmacAlgorithm, string appId = null)
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            using (var hmak = HMAC.Create(hmacAlgorithm))
            {
                byte[] secretKeyByteArray = new byte[hmak.HashSize / 8];
                cryptoProvider.GetBytes(secretKeyByteArray);
                return new HashKeys(appId ?? Guid.NewGuid().ToString(), Convert.ToBase64String(secretKeyByteArray), hashAlgorithm, hmacAlgorithm, userId);
            }
        }
    }
}
