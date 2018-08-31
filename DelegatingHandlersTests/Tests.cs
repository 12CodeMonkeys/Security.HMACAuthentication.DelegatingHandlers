using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.HMACAuthentication;
using Security.HMACAuthentication.DelegatingHandlers.DelegatingHandlers;
using Shouldly;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading;

namespace DelegatingHandlersTests
{
    [TestClass]
    public class Tests
    {
        public static HashKeys HashKeys = HashKeys.GenerateHashKeys("User1", "MD5", "HMACSHA256", Guid.NewGuid().ToString());
        
        [TestMethod]
        public void SendAcync_using_message_invoker_suould_succeed()
        {
            // arrange
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://localhost");
            var handler = new HMACAuthrizationDelegatingHandler(HashKeys);
            var invoker = new HttpMessageInvoker(handler);

            // action
            var result = invoker.SendAsync(httpRequestMessage, new CancellationToken()).Result;

            // assert
            result.ShouldNotBeNull();
            result.RequestMessage.Headers.Contains("Authorization").ShouldBeTrue();
            result.RequestMessage.Headers.GetValues("Authorization").ShouldHaveSingleItem();
            result.RequestMessage.Headers.GetValues("Authorization").SingleOrDefault().ShouldStartWith("amx ");
        }

        [TestMethod]
        public void SendAcync_using_http_client_suould_succeed()
        {
            // arrange
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://localhost");
            var handler = new HMACAuthrizationDelegatingHandler(HashKeys);
            var httpClient = new HttpClient(handler);

            // action
            var result = httpClient.SendAsync(httpRequestMessage, new CancellationToken()).Result;

            // assert
            result.ShouldNotBeNull();
            result.RequestMessage.Headers.Contains("Authorization").ShouldBeTrue();
            result.RequestMessage.Headers.GetValues("Authorization").ShouldHaveSingleItem();
            result.RequestMessage.Headers.GetValues("Authorization").SingleOrDefault().ShouldStartWith("amx ");
        }

        [TestMethod]
        public void GetSend_using_http_client_suould_succeed()
        {
            // arrange
            var handler = new HMACAuthrizationDelegatingHandler(HashKeys);
            var httpClient = new HttpClient(handler);

            // action
            var result = httpClient.GetAsync("http://localhost").Result;

            // assert
            result.ShouldNotBeNull();
            result.RequestMessage.Headers.Contains("Authorization").ShouldBeTrue();
            result.RequestMessage.Headers.GetValues("Authorization").ShouldHaveSingleItem();
            result.RequestMessage.Headers.GetValues("Authorization").SingleOrDefault().ShouldStartWith("amx ");
        }
    }
}
