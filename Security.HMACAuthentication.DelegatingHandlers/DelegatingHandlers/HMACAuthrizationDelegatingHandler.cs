using Security.HMACAuthentication.Interfaces;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Security.HMACAuthentication.DelegatingHandlers.DelegatingHandlers
{
    public class HMACAuthrizationDelegatingHandler : DelegatingHandler
    {
        private readonly IHashKeys _hashKeys;
        private readonly IAuthorisationHeaderSerializer _authHeaderSerializer;
        private readonly ISigner _signer;

        public HMACAuthrizationDelegatingHandler(IHashKeys hashKeys)
        {
            _hashKeys = hashKeys;
            _signer = new Signer();
            _authHeaderSerializer = new AuthorisationHeaderSerializer();
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var authHeader = new AuthorizationHeader(_hashKeys.APPId);

            authHeader.Signature = await _signer.SignAsync(request, authHeader, _hashKeys);

            request.Headers.Authorization = new AuthenticationHeaderValue(_authHeaderSerializer.AuthenticationScheme, _authHeaderSerializer.Serialize(authHeader));

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}
