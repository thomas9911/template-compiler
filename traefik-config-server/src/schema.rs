#![allow(clippy::redundant_closure_call)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::match_single_binding)]
#![allow(clippy::clone_on_copy)]

use serde::{Deserialize, Serialize};

#[doc = "The AddPrefix middleware updates the URL Path of the request before forwarding it."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddPrefixMiddleware {
    #[doc = "prefix is the string to add before the current path in the requested URL. It should include the leading slash (/)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}
impl From<&AddPrefixMiddleware> for AddPrefixMiddleware {
    fn from(value: &AddPrefixMiddleware) -> Self {
        value.clone()
    }
}
impl AddPrefixMiddleware {
    pub fn builder() -> builder::AddPrefixMiddleware {
        builder::AddPrefixMiddleware::default()
    }
}
#[doc = "The BasicAuth middleware is a quick way to restrict access to your services to known users. If both users and usersFile are provided, the two are merged. The contents of usersFile have precedence over the values in users."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BasicAuthMiddleware {
    #[doc = "You can define a header field to store the authenticated user using the headerField option."]
    #[serde(
        rename = "headerField",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub header_field: Option<String>,
    #[doc = "You can customize the realm for the authentication with the realm option. The default value is traefik."]
    #[serde(default = "defaults::basic_auth_middleware_realm")]
    pub realm: String,
    #[doc = "Set the removeHeader option to true to remove the authorization header before forwarding the request to your service. (Default value is false.)"]
    #[serde(rename = "removeHeader", default)]
    pub remove_header: bool,
    #[doc = "The users option is an array of authorized users. Each user will be declared using the `name:hashed-password` format."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    #[doc = "The usersFile option is the path to an external file that contains the authorized users for the middleware.\n\nThe file content is a list of `name:hashed-password`."]
    #[serde(rename = "usersFile", default, skip_serializing_if = "Option::is_none")]
    pub users_file: Option<String>,
}
impl From<&BasicAuthMiddleware> for BasicAuthMiddleware {
    fn from(value: &BasicAuthMiddleware) -> Self {
        value.clone()
    }
}
impl BasicAuthMiddleware {
    pub fn builder() -> builder::BasicAuthMiddleware {
        builder::BasicAuthMiddleware::default()
    }
}
#[doc = "The Buffering middleware gives you control on how you want to read the requests before sending them to services.\n\nWith Buffering, Traefik reads the entire request into memory (possibly buffering large requests into disk), and rejects requests that are over a specified limit.\n\nThis can help services deal with large data (multipart/form-data for example), and can minimize time spent sending data to a service."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BufferingMiddleware {
    #[doc = "With the maxRequestBodyBytes option, you can configure the maximum allowed body size for the request (in Bytes).\n\nIf the request exceeds the allowed size, it is not forwarded to the service and the client gets a 413 (Request Entity Too Large) response."]
    #[serde(
        rename = "maxRequestBodyBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_request_body_bytes: Option<i64>,
    #[doc = "With the maxResponseBodyBytes option, you can configure the maximum allowed response size from the service (in Bytes).\n\nIf the response exceeds the allowed size, it is not forwarded to the client. The client gets a 413 (Request Entity Too Large) response instead."]
    #[serde(
        rename = "maxResponseBodyBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_response_body_bytes: Option<i64>,
    #[doc = "You can configure a threshold (in Bytes) from which the request will be buffered on disk instead of in memory with the memRequestBodyBytes option."]
    #[serde(
        rename = "memRequestBodyBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mem_request_body_bytes: Option<i64>,
    #[doc = "You can configure a threshold (in Bytes) from which the response will be buffered on disk instead of in memory with the memResponseBodyBytes option."]
    #[serde(
        rename = "memResponseBodyBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mem_response_body_bytes: Option<i64>,
    #[doc = "You can have the Buffering middleware replay the request with the help of the retryExpression option."]
    #[serde(
        rename = "retryExpression",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retry_expression: Option<String>,
}
impl From<&BufferingMiddleware> for BufferingMiddleware {
    fn from(value: &BufferingMiddleware) -> Self {
        value.clone()
    }
}
impl BufferingMiddleware {
    pub fn builder() -> builder::BufferingMiddleware {
        builder::BufferingMiddleware::default()
    }
}
#[doc = "The Chain middleware enables you to define reusable combinations of other pieces of middleware. It makes reusing the same groups easier."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainMiddleware {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub middlewares: Vec<String>,
}
impl From<&ChainMiddleware> for ChainMiddleware {
    fn from(value: &ChainMiddleware) -> Self {
        value.clone()
    }
}
impl ChainMiddleware {
    pub fn builder() -> builder::ChainMiddleware {
        builder::ChainMiddleware::default()
    }
}
#[doc = "The circuit breaker protects your system from stacking requests to unhealthy services (resulting in cascading failures).\n\nWhen your system is healthy, the circuit is closed (normal operations). When your system becomes unhealthy, the circuit becomes open and the requests are no longer forwarded (but handled by a fallback mechanism).\n\nTo assess if your system is healthy, the circuit breaker constantly monitors the services."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerMiddleware {
    #[doc = "The interval between successive checks of the circuit breaker condition (when in standby state)"]
    #[serde(
        rename = "checkPeriod",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub check_period: Option<String>,
    #[doc = "You can specify an expression that, once matched, will trigger the circuit breaker (and apply the fallback mechanism instead of calling your services)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[doc = "The duration for which the circuit breaker will wait before trying to recover (from a tripped state)."]
    #[serde(
        rename = "fallbackDuration",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub fallback_duration: Option<String>,
    #[doc = "The duration for which the circuit breaker will try to recover (as soon as it is in recovering state)."]
    #[serde(
        rename = "recoveryDuration",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_duration: Option<String>,
}
impl From<&CircuitBreakerMiddleware> for CircuitBreakerMiddleware {
    fn from(value: &CircuitBreakerMiddleware) -> Self {
        value.clone()
    }
}
impl CircuitBreakerMiddleware {
    pub fn builder() -> builder::CircuitBreakerMiddleware {
        builder::CircuitBreakerMiddleware::default()
    }
}
#[doc = "The Compress middleware enables the gzip compression."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompressMiddleware {
    #[doc = "excludedContentTypes specifies a list of content types to compare the Content-Type header of the incoming requests to before compressing.\n\nThe requests with content types defined in excludedContentTypes are not compressed.\n\nContent types are compared in a case-insensitive, whitespace-ignored manner."]
    #[serde(
        rename = "excludedContentTypes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub excluded_content_types: Vec<String>,
    #[doc = "specifies the minimum amount of bytes a response body must have to be compressed."]
    #[serde(
        rename = "minResponseBodyBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub min_response_body_bytes: Option<i64>,
}
impl From<&CompressMiddleware> for CompressMiddleware {
    fn from(value: &CompressMiddleware) -> Self {
        value.clone()
    }
}
impl CompressMiddleware {
    pub fn builder() -> builder::CompressMiddleware {
        builder::CompressMiddleware::default()
    }
}
#[doc = "The Content-Type middleware - or rather its unique autoDetect option - specifies whether to let the Content-Type header, if it has not been set by the backend, be automatically set to a value derived from the contents of the response.\n\nAs a proxy, the default behavior should be to leave the header alone, regardless of what the backend did with it. However, the historic default was to always auto-detect and set the header if it was nil, and it is going to be kept that way in order to support users currently relying on it. This middleware exists to enable the correct behavior until at least the default one can be changed in a future version."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentTypeMiddleware {
    #[doc = "autoDetect specifies whether to let the Content-Type header, if it has not been set by the backend, be automatically set to a value derived from the contents of the response."]
    #[serde(rename = "autoDetect", default)]
    pub auto_detect: bool,
}
impl From<&ContentTypeMiddleware> for ContentTypeMiddleware {
    fn from(value: &ContentTypeMiddleware) -> Self {
        value.clone()
    }
}
impl ContentTypeMiddleware {
    pub fn builder() -> builder::ContentTypeMiddleware {
        builder::ContentTypeMiddleware::default()
    }
}
#[doc = "The DigestAuth middleware is a quick way to restrict access to your services to known users. If both users and usersFile are provided, the two are merged. The contents of usersFile have precedence over the values in users."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DigestAuthMiddleware {
    #[doc = "You can customize the header field for the authenticated user using the headerField option."]
    #[serde(
        rename = "headerField",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub header_field: Option<String>,
    #[doc = "You can customize the realm for the authentication with the realm option. The default value is traefik."]
    #[serde(default = "defaults::digest_auth_middleware_realm")]
    pub realm: String,
    #[doc = "Set the removeHeader option to true to remove the authorization header before forwarding the request to your service. (Default value is false.)"]
    #[serde(rename = "removeHeader", default)]
    pub remove_header: bool,
    #[doc = "The users option is an array of authorized users. Each user will be declared using the `name:realm:encoded-password` format."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    #[doc = "The usersFile option is the path to an external file that contains the authorized users for the middleware.\n\nThe file content is a list of `name:realm:encoded-password`."]
    #[serde(rename = "usersFile", default, skip_serializing_if = "Option::is_none")]
    pub users_file: Option<String>,
}
impl From<&DigestAuthMiddleware> for DigestAuthMiddleware {
    fn from(value: &DigestAuthMiddleware) -> Self {
        value.clone()
    }
}
impl DigestAuthMiddleware {
    pub fn builder() -> builder::DigestAuthMiddleware {
        builder::DigestAuthMiddleware::default()
    }
}
#[doc = "The ErrorPage middleware returns a custom page in lieu of the default, according to configured ranges of HTTP Status codes. The error page itself is not hosted by Traefik."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorsMiddleware {
    #[doc = "The URL for the error page (hosted by service). You can use {status} in the query, that will be replaced by the received status code."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[doc = "The service that will serve the new requested error page."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[doc = "The status that will trigger the error page.\n\nThe status code ranges are inclusive (500-599 will trigger with every code between 500 and 599, 500 and 599 included). You can define either a status code like 500 or ranges with a syntax like 500-599."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<String>,
}
impl From<&ErrorsMiddleware> for ErrorsMiddleware {
    fn from(value: &ErrorsMiddleware) -> Self {
        value.clone()
    }
}
impl ErrorsMiddleware {
    pub fn builder() -> builder::ErrorsMiddleware {
        builder::ErrorsMiddleware::default()
    }
}
#[doc = "The ForwardAuth middleware delegate the authentication to an external service. If the service response code is 2XX, access is granted and the original request is performed. Otherwise, the response from the authentication server is returned."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardAuthMiddleware {
    #[doc = "The address option defines the authentication server address."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[doc = "The authRequestHeaders option is the list of the headers to copy from the request to the authentication server."]
    #[serde(
        rename = "authRequestHeaders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub auth_request_headers: Vec<String>,
    #[doc = "The authResponseHeaders option is the list of the headers to copy from the authentication server to the request."]
    #[serde(
        rename = "authResponseHeaders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub auth_response_headers: Vec<String>,
    #[doc = "The authResponseHeadersRegex option is the regex to match headers to copy from the authentication server response and set on forwarded request, after stripping all headers that match the regex."]
    #[serde(
        rename = "authResponseHeadersRegex",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_response_headers_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ForwardAuthMiddlewareTls>,
    #[doc = "Set the trustForwardHeader option to true to trust all the existing X-Forwarded-* headers."]
    #[serde(
        rename = "trustForwardHeader",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trust_forward_header: Option<bool>,
}
impl From<&ForwardAuthMiddleware> for ForwardAuthMiddleware {
    fn from(value: &ForwardAuthMiddleware) -> Self {
        value.clone()
    }
}
impl ForwardAuthMiddleware {
    pub fn builder() -> builder::ForwardAuthMiddleware {
        builder::ForwardAuthMiddleware::default()
    }
}
#[doc = "The tls option is the TLS configuration from Traefik to the authentication server."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForwardAuthMiddlewareTls {
    #[doc = "Certificate Authority used for the secured connection to the authentication server."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    #[doc = "Policy used for the secured connection with TLS Client Authentication to the authentication server. Requires tls.ca to be defined."]
    #[serde(
        rename = "caOptional",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ca_optional: Option<bool>,
    #[doc = "Public certificate used for the secured connection to the authentication server."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[doc = "If insecureSkipVerify is true, TLS for the connection to authentication server accepts any certificate presented by the server and any host name in that certificate."]
    #[serde(
        rename = "insecureSkipVerify",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub insecure_skip_verify: Option<bool>,
    #[doc = "Private certificate used for the secure connection to the authentication server."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}
impl From<&ForwardAuthMiddlewareTls> for ForwardAuthMiddlewareTls {
    fn from(value: &ForwardAuthMiddlewareTls) -> Self {
        value.clone()
    }
}
impl ForwardAuthMiddlewareTls {
    pub fn builder() -> builder::ForwardAuthMiddlewareTls {
        builder::ForwardAuthMiddlewareTls::default()
    }
}
#[doc = "The Headers middleware can manage the requests/responses headers."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersMiddleware {
    #[doc = "The accessControlAllowCredentials indicates whether the request can include user credentials."]
    #[serde(
        rename = "accessControlAllowCredentials",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_control_allow_credentials: Option<bool>,
    #[doc = "The accessControlAllowHeaders indicates which header field names can be used as part of the request."]
    #[serde(
        rename = "accessControlAllowHeaders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub access_control_allow_headers: Vec<String>,
    #[doc = "The accessControlAllowMethods indicates which methods can be used during requests."]
    #[serde(
        rename = "accessControlAllowMethods",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub access_control_allow_methods: Vec<String>,
    #[doc = "The accessControlAllowOriginList indicates whether a resource can be shared by returning different values.\n\nA wildcard origin * can also be configured, and will match all requests. If this value is set by a backend server, it will be overwritten by Traefik\n\nThis value can contain a list of allowed origins."]
    #[serde(
        rename = "accessControlAllowOriginList",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub access_control_allow_origin_list: Vec<String>,
    #[doc = "The accessControlAllowOriginListRegex option is the counterpart of the accessControlAllowOriginList option with regular expressions instead of origin values."]
    #[serde(
        rename = "accessControlAllowOriginListRegex",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub access_control_allow_origin_list_regex: Vec<String>,
    #[doc = "The accessControlExposeHeaders indicates which headers are safe to expose to the api of a CORS API specification."]
    #[serde(
        rename = "accessControlExposeHeaders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub access_control_expose_headers: Vec<String>,
    #[doc = "The accessControlMaxAge indicates how long (in seconds) a preflight request can be cached."]
    #[serde(
        rename = "accessControlMaxAge",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_control_max_age: Option<i64>,
    #[doc = "The addVaryHeader is used in conjunction with accessControlAllowOriginList to determine whether the vary header should be added or modified to demonstrate that server responses can differ based on the value of the origin header."]
    #[serde(
        rename = "addVaryHeader",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub add_vary_header: Option<bool>,
    #[doc = "The allowedHosts option lists fully qualified domain names that are allowed."]
    #[serde(
        rename = "allowedHosts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_hosts: Vec<String>,
    #[doc = "Set browserXssFilter to true to add the X-XSS-Protection header with the value 1; mode=block."]
    #[serde(
        rename = "browserXssFilter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_xss_filter: Option<bool>,
    #[doc = "The contentSecurityPolicy option allows the Content-Security-Policy header value to be set with a custom value."]
    #[serde(
        rename = "contentSecurityPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_security_policy: Option<String>,
    #[doc = "Set contentTypeNosniff to true to add the X-Content-Type-Options header with the value nosniff."]
    #[serde(
        rename = "contentTypeNosniff",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type_nosniff: Option<bool>,
    #[doc = "The customBrowserXssValue option allows the X-XSS-Protection header value to be set with a custom value. This overrides the BrowserXssFilter option."]
    #[serde(
        rename = "customBrowserXSSValue",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_browser_xss_value: Option<String>,
    #[doc = "The customFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option."]
    #[serde(
        rename = "customFrameOptionsValue",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_frame_options_value: Option<String>,
    #[serde(
        rename = "customRequestHeaders",
        default,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub custom_request_headers: std::collections::HashMap<String, String>,
    #[serde(
        rename = "customResponseHeaders",
        default,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub custom_response_headers: std::collections::HashMap<String, String>,
    #[doc = "The featurePolicy allows sites to control browser features."]
    #[serde(
        rename = "featurePolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub feature_policy: Option<String>,
    #[doc = "Set forceSTSHeader to true, to add the STS header even when the connection is HTTP."]
    #[serde(
        rename = "forceSTSHeader",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub force_sts_header: Option<bool>,
    #[doc = "Set frameDeny to true to add the X-Frame-Options header with the value of DENY."]
    #[serde(rename = "frameDeny", default, skip_serializing_if = "Option::is_none")]
    pub frame_deny: Option<bool>,
    #[doc = "The hostsProxyHeaders option is a set of header keys that may hold a proxied hostname value for the request."]
    #[serde(
        rename = "hostsProxyHeaders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub hosts_proxy_headers: Vec<String>,
    #[doc = "Set isDevelopment to true when developing. The AllowedHosts, SSL, and STS options can cause some unwanted effects. Usually testing happens on http, not https, and on localhost, not your production domain.\nIf you would like your development environment to mimic production with complete Host blocking, SSL redirects, and STS headers, leave this as false."]
    #[serde(
        rename = "isDevelopment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_development: Option<bool>,
    #[doc = "The permissionsPolicy allows sites to control browser features."]
    #[serde(
        rename = "permissionsPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub permissions_policy: Option<String>,
    #[doc = "The publicKey implements HPKP to prevent MITM attacks with forged certificates."]
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[doc = "The referrerPolicy allows sites to control when browsers will pass the Referer header to other sites."]
    #[serde(
        rename = "referrerPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub referrer_policy: Option<String>,
    #[doc = "Set sslForceHost to true and set SSLHost to forced requests to use SSLHost even the ones that are already using SSL."]
    #[serde(
        rename = "sslForceHost",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ssl_force_host: Option<bool>,
    #[doc = "The sslHost option is the host name that is used to redirect http requests to https."]
    #[serde(rename = "sslHost", default, skip_serializing_if = "Option::is_none")]
    pub ssl_host: Option<String>,
    #[serde(
        rename = "sslProxyHeaders",
        default,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub ssl_proxy_headers: std::collections::HashMap<String, String>,
    #[doc = "The sslRedirect is set to true, then only allow https requests."]
    #[serde(
        rename = "sslRedirect",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ssl_redirect: Option<bool>,
    #[doc = "Set the sslTemporaryRedirect to true to force an SSL redirection using a 302 (instead of a 301)."]
    #[serde(
        rename = "sslTemporaryRedirect",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ssl_temporary_redirect: Option<bool>,
    #[doc = "The stsIncludeSubdomains is set to true, the includeSubDomains directive will be appended to the Strict-Transport-Security header."]
    #[serde(
        rename = "stsIncludeSubdomains",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sts_include_subdomains: Option<bool>,
    #[doc = "Set stsPreload to true to have the preload flag appended to the Strict-Transport-Security header."]
    #[serde(
        rename = "stsPreload",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sts_preload: Option<bool>,
    #[doc = "The stsSeconds is the max-age of the Strict-Transport-Security header. If set to 0, would NOT include the header."]
    #[serde(
        rename = "stsSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sts_seconds: Option<i64>,
}
impl From<&HeadersMiddleware> for HeadersMiddleware {
    fn from(value: &HeadersMiddleware) -> Self {
        value.clone()
    }
}
impl HeadersMiddleware {
    pub fn builder() -> builder::HeadersMiddleware {
        builder::HeadersMiddleware::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFailoverService {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
    #[serde(
        rename = "healthCheck",
        default,
        skip_serializing_if = "serde_json::Map::is_empty"
    )]
    pub health_check: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}
impl From<&HttpFailoverService> for HttpFailoverService {
    fn from(value: &HttpFailoverService) -> Self {
        value.clone()
    }
}
impl HttpFailoverService {
    pub fn builder() -> builder::HttpFailoverService {
        builder::HttpFailoverService::default()
    }
}
#[doc = "The load balancers are able to load balance the requests between multiple instances of your programs.\n\nEach service has a load-balancer, even if there is only one server to forward traffic to."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpLoadBalancerService {
    #[serde(
        rename = "healthCheck",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub health_check: Option<HttpLoadBalancerServiceHealthCheck>,
    #[doc = "The passHostHeader allows to forward client Host header to server. By default, passHostHeader is true."]
    #[serde(rename = "passHostHeader", default = "defaults::default_bool::<true>")]
    pub pass_host_header: bool,
    #[serde(
        rename = "responseForwarding",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub response_forwarding: Option<HttpLoadBalancerServiceResponseForwarding>,
    #[doc = "Servers declare a single instance of your program."]
    pub servers: Vec<HttpLoadBalancerServiceServersItem>,
    #[serde(
        rename = "serversTransport",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub servers_transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<HttpLoadBalancerServiceSticky>,
}
impl From<&HttpLoadBalancerService> for HttpLoadBalancerService {
    fn from(value: &HttpLoadBalancerService) -> Self {
        value.clone()
    }
}
impl HttpLoadBalancerService {
    pub fn builder() -> builder::HttpLoadBalancerService {
        builder::HttpLoadBalancerService::default()
    }
}
#[doc = "Configure health check to remove unhealthy servers from the load balancing rotation. Traefik will consider your servers healthy as long as they return status codes between 2XX and 3XX to the health check requests (carried out every interval). Traefik keeps monitoring the health of unhealthy servers. If a server has recovered (returning 2xx -> 3xx responses again), it will be added back to the load balancer rotation pool."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpLoadBalancerServiceHealthCheck {
    #[doc = "Defines whether redirects should be followed during the health check calls (default: true)."]
    #[serde(rename = "followRedirects", default = "defaults::default_bool::<true>")]
    pub follow_redirects: bool,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub headers: std::collections::HashMap<String, String>,
    #[doc = "If defined, will apply Host header hostname to the health check request."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[doc = "Defines the frequency of the health check calls. Interval is to be given in a format understood by `time.ParseDuration`. The interval must be greater than the timeout. If configuration doesn't reflect this, the interval will be set to timeout + 1 second."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[doc = "If defined, will apply this Method for the health check request."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[doc = "path is appended to the server URL to set the health check endpoint."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[doc = "If defined, will replace the server URL port for the health check endpoint."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    #[doc = "If defined, will replace the server URL scheme for the health check endpoint"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[doc = "Defines the maximum duration Traefik will wait for a health check request before considering the server failed (unhealthy). Timeout is to be given in a format understood by `time.ParseDuration`."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}
impl From<&HttpLoadBalancerServiceHealthCheck> for HttpLoadBalancerServiceHealthCheck {
    fn from(value: &HttpLoadBalancerServiceHealthCheck) -> Self {
        value.clone()
    }
}
impl HttpLoadBalancerServiceHealthCheck {
    pub fn builder() -> builder::HttpLoadBalancerServiceHealthCheck {
        builder::HttpLoadBalancerServiceHealthCheck::default()
    }
}
#[doc = "Defines how Traefik forwards the response from the backend server to the client."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpLoadBalancerServiceResponseForwarding {
    #[doc = "Specifies the interval in between flushes to the client while copying the response body. It is a duration in milliseconds, defaulting to 100. A negative value means to flush immediately after each write to the client. The flushInterval is ignored when ReverseProxy recognizes a response as a streaming response; for such responses, writes are flushed to the client immediately."]
    #[serde(
        rename = "flushInterval",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub flush_interval: Option<String>,
}
impl From<&HttpLoadBalancerServiceResponseForwarding>
    for HttpLoadBalancerServiceResponseForwarding
{
    fn from(value: &HttpLoadBalancerServiceResponseForwarding) -> Self {
        value.clone()
    }
}
impl HttpLoadBalancerServiceResponseForwarding {
    pub fn builder() -> builder::HttpLoadBalancerServiceResponseForwarding {
        builder::HttpLoadBalancerServiceResponseForwarding::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpLoadBalancerServiceServersItem {
    #[doc = "The url option point to a specific instance. Paths in the servers' url have no effect. If you want the requests to be sent to a specific path on your servers, configure your routers to use a corresponding middleware (e.g. the AddPrefix or ReplacePath) middlewares."]
    pub url: String,
}
impl From<&HttpLoadBalancerServiceServersItem> for HttpLoadBalancerServiceServersItem {
    fn from(value: &HttpLoadBalancerServiceServersItem) -> Self {
        value.clone()
    }
}
impl HttpLoadBalancerServiceServersItem {
    pub fn builder() -> builder::HttpLoadBalancerServiceServersItem {
        builder::HttpLoadBalancerServiceServersItem::default()
    }
}
#[doc = "When sticky sessions are enabled, a cookie is set on the initial request and response to let the client know which server handles the first response. On subsequent requests, to keep the session alive with the same server, the client should resend the same cookie."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpLoadBalancerServiceSticky {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<HttpLoadBalancerServiceStickyCookie>,
}
impl From<&HttpLoadBalancerServiceSticky> for HttpLoadBalancerServiceSticky {
    fn from(value: &HttpLoadBalancerServiceSticky) -> Self {
        value.clone()
    }
}
impl HttpLoadBalancerServiceSticky {
    pub fn builder() -> builder::HttpLoadBalancerServiceSticky {
        builder::HttpLoadBalancerServiceSticky::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpLoadBalancerServiceStickyCookie {
    #[serde(rename = "httpOnly", default)]
    pub http_only: bool,
    #[doc = "The default cookie name is an abbreviation of a sha1 (ex: _1d52e)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Can be none, lax, strict or empty."]
    #[serde(rename = "sameSite", default)]
    pub same_site: String,
    #[serde(default)]
    pub secure: bool,
}
impl From<&HttpLoadBalancerServiceStickyCookie> for HttpLoadBalancerServiceStickyCookie {
    fn from(value: &HttpLoadBalancerServiceStickyCookie) -> Self {
        value.clone()
    }
}
impl HttpLoadBalancerServiceStickyCookie {
    pub fn builder() -> builder::HttpLoadBalancerServiceStickyCookie {
        builder::HttpLoadBalancerServiceStickyCookie::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum HttpMiddleware {
    Variant0 {
        #[serde(rename = "addPrefix", default, skip_serializing_if = "Option::is_none")]
        add_prefix: Option<AddPrefixMiddleware>,
    },
    Variant1 {
        #[serde(rename = "basicAuth", default, skip_serializing_if = "Option::is_none")]
        basic_auth: Option<BasicAuthMiddleware>,
    },
    Variant2 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        buffering: Option<BufferingMiddleware>,
    },
    Variant3 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chain: Option<ChainMiddleware>,
    },
    Variant4 {
        #[serde(
            rename = "circuitBreaker",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        circuit_breaker: Option<CircuitBreakerMiddleware>,
    },
    Variant5 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        compress: Option<CompressMiddleware>,
    },
    Variant6 {
        #[serde(
            rename = "contentType",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        content_type: Option<ContentTypeMiddleware>,
    },
    Variant7 {
        #[serde(
            rename = "digestAuth",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        digest_auth: Option<DigestAuthMiddleware>,
    },
    Variant8 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        errors: Option<ErrorsMiddleware>,
    },
    Variant9 {
        #[serde(
            rename = "forwardAuth",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        forward_auth: Option<ForwardAuthMiddleware>,
    },
    Variant10 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<HeadersMiddleware>,
    },
    Variant11 {
        #[serde(
            rename = "ipWhiteList",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        ip_white_list: Option<IpWhiteListMiddleware>,
    },
    Variant12 {
        #[serde(
            rename = "inFlightReq",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        in_flight_req: Option<InFlightReqMiddleware>,
    },
    Variant13 {
        #[serde(
            rename = "passTLSClientCert",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pass_tls_client_cert: Option<PassTlsClientCertMiddleware>,
    },
    Variant14 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plugin: Option<PluginMiddleware>,
    },
    Variant15 {
        #[serde(rename = "rateLimit", default, skip_serializing_if = "Option::is_none")]
        rate_limit: Option<RateLimitMiddleware>,
    },
    Variant16 {
        #[serde(
            rename = "redirectRegex",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        redirect_regex: Option<RedirectRegexMiddleware>,
    },
    Variant17 {
        #[serde(
            rename = "redirectScheme",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        redirect_scheme: Option<RedirectSchemeMiddleware>,
    },
    Variant18 {
        #[serde(
            rename = "replacePath",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        replace_path: Option<ReplacePathMiddleware>,
    },
    Variant19 {
        #[serde(
            rename = "replacePathRegex",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        replace_path_regex: Option<ReplacePathRegexMiddleware>,
    },
    Variant20 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry: Option<RetryMiddleware>,
    },
    Variant21 {
        #[serde(
            rename = "stripPrefix",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        strip_prefix: Option<StripPrefixMiddleware>,
    },
    Variant22 {
        #[serde(
            rename = "stripPrefixRegex",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        strip_prefix_regex: Option<StripPrefixRegexMiddleware>,
    },
}
impl From<&HttpMiddleware> for HttpMiddleware {
    fn from(value: &HttpMiddleware) -> Self {
        value.clone()
    }
}
#[doc = "The mirroring is able to mirror requests sent to a service to other services. Please note that by default the whole request is buffered in memory while it is being mirrored. See the maxBodySize option for how to modify this behaviour."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpMirroringService {
    #[serde(
        rename = "healthCheck",
        default,
        skip_serializing_if = "serde_json::Map::is_empty"
    )]
    pub health_check: serde_json::Map<String, serde_json::Value>,
    #[doc = "maxBodySize is the maximum size allowed for the body of the request. If the body is larger, the request is not mirrored. Default value is -1, which means unlimited size."]
    #[serde(rename = "maxBodySize", default = "defaults::default_i64::<i64, -1>")]
    pub max_body_size: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirrors: Vec<HttpMirroringServiceMirrorsItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}
impl From<&HttpMirroringService> for HttpMirroringService {
    fn from(value: &HttpMirroringService) -> Self {
        value.clone()
    }
}
impl HttpMirroringService {
    pub fn builder() -> builder::HttpMirroringService {
        builder::HttpMirroringService::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpMirroringServiceMirrorsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<f64>,
}
impl From<&HttpMirroringServiceMirrorsItem> for HttpMirroringServiceMirrorsItem {
    fn from(value: &HttpMirroringServiceMirrorsItem) -> Self {
        value.clone()
    }
}
impl HttpMirroringServiceMirrorsItem {
    pub fn builder() -> builder::HttpMirroringServiceMirrorsItem {
        builder::HttpMirroringServiceMirrorsItem::default()
    }
}
#[doc = "A router is in charge of connecting incoming requests to the services that can handle them. In the process, routers may use pieces of middleware to update the request, or act before forwarding the request to the service."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRouter {
    #[doc = "If not specified, HTTP routers will accept requests from all defined entry points. If you want to limit the router scope to a set of entry points, set the entryPoints option."]
    #[serde(rename = "entryPoints", default, skip_serializing_if = "Vec::is_empty")]
    pub entry_points: Vec<String>,
    #[doc = "You can attach a list of middlewares to each HTTP router. The middlewares will take effect only if the rule matches, and before forwarding the request to the service. Middlewares are applied in the same order as their declaration in router."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub middlewares: Vec<String>,
    #[doc = "To avoid path overlap, routes are sorted, by default, in descending order using rules length. The priority is directly equal to the length of the rule, and so the longest length has the highest priority. A value of 0 for the priority is ignored: priority = 0 means that the default rules length sorting is used."]
    #[serde(default)]
    pub priority: u64,
    #[doc = "Rules are a set of matchers configured with values, that determine if a particular request matches specific criteria. If the rule is verified, the router becomes active, calls middlewares, and then forwards the request to the service."]
    pub rule: String,
    #[doc = "Each request must eventually be handled by a service, which is why each router definition should include a service target, which is basically where the request will be passed along to. HTTP routers can only target HTTP services (not TCP services)."]
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<HttpRouterTls>,
}
impl From<&HttpRouter> for HttpRouter {
    fn from(value: &HttpRouter) -> Self {
        value.clone()
    }
}
impl HttpRouter {
    pub fn builder() -> builder::HttpRouter {
        builder::HttpRouter::default()
    }
}
#[doc = "When a TLS section is specified, it instructs Traefik that the current router is dedicated to HTTPS requests only (and that the router should ignore HTTP (non TLS) requests). Traefik will terminate the SSL connections (meaning that it will send decrypted data to the services). If you need to define the same route for both HTTP and HTTPS requests, you will need to define two different routers: one with the tls section, one without."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpRouterTls {
    #[doc = "If certResolver is defined, Traefik will try to generate certificates based on routers Host & HostSNI rules."]
    #[serde(
        rename = "certResolver",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cert_resolver: Option<String>,
    #[doc = "You can set SANs (alternative domains) for each main domain. Every domain must have A/AAAA records pointing to Traefik. Each domain & SAN will lead to a certificate request."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<HttpRouterTlsDomainsItem>,
    #[doc = "The options field enables fine-grained control of the TLS parameters. It refers to a TLS Options and will be applied only if a Host rule is defined."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
}
impl From<&HttpRouterTls> for HttpRouterTls {
    fn from(value: &HttpRouterTls) -> Self {
        value.clone()
    }
}
impl HttpRouterTls {
    pub fn builder() -> builder::HttpRouterTls {
        builder::HttpRouterTls::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpRouterTlsDomainsItem {
    #[doc = "Main defines the main domain name."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    #[doc = "SANs defines the subject alternative domain names."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
}
impl From<&HttpRouterTlsDomainsItem> for HttpRouterTlsDomainsItem {
    fn from(value: &HttpRouterTlsDomainsItem) -> Self {
        value.clone()
    }
}
impl HttpRouterTlsDomainsItem {
    pub fn builder() -> builder::HttpRouterTlsDomainsItem {
        builder::HttpRouterTlsDomainsItem::default()
    }
}
#[doc = "The Services are responsible for configuring how to reach the actual services that will eventually handle the incoming requests."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum HttpService {
    Variant0 {
        #[serde(
            rename = "loadBalancer",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        load_balancer: Option<HttpLoadBalancerService>,
    },
    Variant1 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        weighted: Option<HttpWeightedService>,
    },
    Variant2 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mirroring: Option<HttpMirroringService>,
    },
    Variant3 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failover: Option<HttpFailoverService>,
    },
}
impl From<&HttpService> for HttpService {
    fn from(value: &HttpService) -> Self {
        value.clone()
    }
}
#[doc = "The WRR is able to load balance the requests between multiple services based on weights.\n\nThis strategy is only available to load balance between services and not between servers."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpWeightedService {
    #[serde(
        rename = "healthCheck",
        default,
        skip_serializing_if = "serde_json::Map::is_empty"
    )]
    pub health_check: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<HttpWeightedServiceServicesItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<HttpWeightedServiceSticky>,
}
impl From<&HttpWeightedService> for HttpWeightedService {
    fn from(value: &HttpWeightedService) -> Self {
        value.clone()
    }
}
impl HttpWeightedService {
    pub fn builder() -> builder::HttpWeightedService {
        builder::HttpWeightedService::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpWeightedServiceServicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
}
impl From<&HttpWeightedServiceServicesItem> for HttpWeightedServiceServicesItem {
    fn from(value: &HttpWeightedServiceServicesItem) -> Self {
        value.clone()
    }
}
impl HttpWeightedServiceServicesItem {
    pub fn builder() -> builder::HttpWeightedServiceServicesItem {
        builder::HttpWeightedServiceServicesItem::default()
    }
}
#[doc = "When sticky sessions are enabled, a cookie is set on the initial request and response to let the client know which server handles the first response. On subsequent requests, to keep the session alive with the same server, the client should resend the same cookie."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpWeightedServiceSticky {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<HttpWeightedServiceStickyCookie>,
}
impl From<&HttpWeightedServiceSticky> for HttpWeightedServiceSticky {
    fn from(value: &HttpWeightedServiceSticky) -> Self {
        value.clone()
    }
}
impl HttpWeightedServiceSticky {
    pub fn builder() -> builder::HttpWeightedServiceSticky {
        builder::HttpWeightedServiceSticky::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpWeightedServiceStickyCookie {
    #[serde(rename = "httpOnly", default)]
    pub http_only: bool,
    #[doc = "The default cookie name is an abbreviation of a sha1 (ex: _1d52e)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[doc = "Can be none, lax, strict or empty."]
    #[serde(rename = "sameSite", default)]
    pub same_site: String,
    #[serde(default)]
    pub secure: bool,
}
impl From<&HttpWeightedServiceStickyCookie> for HttpWeightedServiceStickyCookie {
    fn from(value: &HttpWeightedServiceStickyCookie) -> Self {
        value.clone()
    }
}
impl HttpWeightedServiceStickyCookie {
    pub fn builder() -> builder::HttpWeightedServiceStickyCookie {
        builder::HttpWeightedServiceStickyCookie::default()
    }
}
#[doc = "To proactively prevent services from being overwhelmed with high load, a limit on the number of simultaneous in-flight requests can be applied."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightReqMiddleware {
    #[doc = "The amount option defines the maximum amount of allowed simultaneous in-flight request. The middleware will return an HTTP 429 Too Many Requests if there are already amount requests in progress (based on the same sourceCriterion strategy)."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(
        rename = "sourceCriterion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_criterion: Option<SourceCriterion>,
}
impl From<&InFlightReqMiddleware> for InFlightReqMiddleware {
    fn from(value: &InFlightReqMiddleware) -> Self {
        value.clone()
    }
}
impl InFlightReqMiddleware {
    pub fn builder() -> builder::InFlightReqMiddleware {
        builder::InFlightReqMiddleware::default()
    }
}
#[doc = "The ipStrategy option defines parameters that set how Traefik will determine the client IP."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpStrategy {
    #[doc = "The depth option tells Traefik to use the X-Forwarded-For header and take the IP located at the depth position (starting from the right). If depth is greater than the total number of IPs in X-Forwarded-For, then the client IP will be empty. depth is ignored if its value is lesser than or equal to 0."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<i64>,
    #[doc = "excludedIPs tells Traefik to scan the X-Forwarded-For header and pick the first IP not in the list. If depth is specified, excludedIPs is ignored."]
    #[serde(rename = "excludedIPs", default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_i_ps: Vec<String>,
}
impl From<&IpStrategy> for IpStrategy {
    fn from(value: &IpStrategy) -> Self {
        value.clone()
    }
}
impl IpStrategy {
    pub fn builder() -> builder::IpStrategy {
        builder::IpStrategy::default()
    }
}
#[doc = "IPWhitelist accepts / refuses requests based on the client IP."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpWhiteListMiddleware {
    #[serde(
        rename = "ipStrategy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ip_strategy: Option<IpStrategy>,
    #[doc = "The sourceRange option sets the allowed IPs (or ranges of allowed IPs by using CIDR notation)."]
    #[serde(rename = "sourceRange", default, skip_serializing_if = "Vec::is_empty")]
    pub source_range: Vec<String>,
}
impl From<&IpWhiteListMiddleware> for IpWhiteListMiddleware {
    fn from(value: &IpWhiteListMiddleware) -> Self {
        value.clone()
    }
}
impl IpWhiteListMiddleware {
    pub fn builder() -> builder::IpWhiteListMiddleware {
        builder::IpWhiteListMiddleware::default()
    }
}
#[doc = "PassTLSClientCert adds in header the selected data from the passed client tls certificate."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PassTlsClientCertMiddleware {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<PassTlsClientCertMiddlewareInfo>,
    #[doc = "The pem option sets the X-Forwarded-Tls-Client-Cert header with the escape certificate."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pem: Option<bool>,
}
impl From<&PassTlsClientCertMiddleware> for PassTlsClientCertMiddleware {
    fn from(value: &PassTlsClientCertMiddleware) -> Self {
        value.clone()
    }
}
impl PassTlsClientCertMiddleware {
    pub fn builder() -> builder::PassTlsClientCertMiddleware {
        builder::PassTlsClientCertMiddleware::default()
    }
}
#[doc = "The info option select the specific client certificate details you want to add to the X-Forwarded-Tls-Client-Cert-Info header. The value of the header will be an escaped concatenation of all the selected certificate details."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PassTlsClientCertMiddlewareInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<PassTlsClientCertMiddlewareInfoIssuer>,
    #[doc = "Set the notAfter option to true to add the Not After information from the Validity part."]
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<bool>,
    #[doc = "Set the notBefore option to true to add the Not Before information from the Validity part."]
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<bool>,
    #[doc = "Set the sans option to true to add the Subject Alternative Name information from the Subject Alternative Name part."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sans: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<PassTlsClientCertMiddlewareInfoSubject>,
}
impl From<&PassTlsClientCertMiddlewareInfo> for PassTlsClientCertMiddlewareInfo {
    fn from(value: &PassTlsClientCertMiddlewareInfo) -> Self {
        value.clone()
    }
}
impl PassTlsClientCertMiddlewareInfo {
    pub fn builder() -> builder::PassTlsClientCertMiddlewareInfo {
        builder::PassTlsClientCertMiddlewareInfo::default()
    }
}
#[doc = "The issuer select the specific client certificate issuer details you want to add to the X-Forwarded-Tls-Client-Cert-Info header."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PassTlsClientCertMiddlewareInfoIssuer {
    #[doc = "Set the commonName option to true to add the commonName information into the issuer."]
    #[serde(
        rename = "commonName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<bool>,
    #[doc = "Set the country option to true to add the country information into the issuer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<bool>,
    #[doc = "Set the domainComponent option to true to add the domainComponent information into the issuer."]
    #[serde(
        rename = "domainComponent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_component: Option<bool>,
    #[doc = "Set the locality option to true to add the locality information into the issuer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<bool>,
    #[doc = "Set the organization option to true to add the organization information into the issuer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<bool>,
    #[doc = "Set the province option to true to add the province information into the issuer."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub province: Option<bool>,
    #[doc = "Set the serialNumber option to true to add the serialNumber information into the issuer."]
    #[serde(
        rename = "serialNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub serial_number: Option<bool>,
}
impl From<&PassTlsClientCertMiddlewareInfoIssuer> for PassTlsClientCertMiddlewareInfoIssuer {
    fn from(value: &PassTlsClientCertMiddlewareInfoIssuer) -> Self {
        value.clone()
    }
}
impl PassTlsClientCertMiddlewareInfoIssuer {
    pub fn builder() -> builder::PassTlsClientCertMiddlewareInfoIssuer {
        builder::PassTlsClientCertMiddlewareInfoIssuer::default()
    }
}
#[doc = "The subject select the specific client certificate subject details you want to add to the X-Forwarded-Tls-Client-Cert-Info header."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PassTlsClientCertMiddlewareInfoSubject {
    #[doc = "Set the commonName option to true to add the commonName information into the subject."]
    #[serde(
        rename = "commonName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<bool>,
    #[doc = "Set the country option to true to add the country information into the subject."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<bool>,
    #[doc = "Set the domainComponent option to true to add the domainComponent information into the subject."]
    #[serde(
        rename = "domainComponent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub domain_component: Option<bool>,
    #[doc = "Set the locality option to true to add the locality information into the subject."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<bool>,
    #[doc = "Set the organization option to true to add the organization information into the subject."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<bool>,
    #[doc = "Set the province option to true to add the province information into the subject."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub province: Option<bool>,
    #[doc = "Set the serialNumber option to true to add the serialNumber information into the subject."]
    #[serde(
        rename = "serialNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub serial_number: Option<bool>,
}
impl From<&PassTlsClientCertMiddlewareInfoSubject> for PassTlsClientCertMiddlewareInfoSubject {
    fn from(value: &PassTlsClientCertMiddlewareInfoSubject) -> Self {
        value.clone()
    }
}
impl PassTlsClientCertMiddlewareInfoSubject {
    pub fn builder() -> builder::PassTlsClientCertMiddlewareInfoSubject {
        builder::PassTlsClientCertMiddlewareInfoSubject::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginMiddleware(
    pub std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>,
);
impl std::ops::Deref for PluginMiddleware {
    type Target = std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>;
    fn deref(
        &self,
    ) -> &std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>> {
        &self.0
    }
}
impl From<PluginMiddleware>
    for std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>
{
    fn from(value: PluginMiddleware) -> Self {
        value.0
    }
}
impl From<&PluginMiddleware> for PluginMiddleware {
    fn from(value: &PluginMiddleware) -> Self {
        value.clone()
    }
}
impl From<std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>>
    for PluginMiddleware
{
    fn from(
        value: std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>,
    ) -> Self {
        Self(value)
    }
}
#[doc = "The RateLimit middleware ensures that services will receive a fair number of requests, and allows one to define what fair is."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitMiddleware {
    #[doc = "average is the maximum rate, by default in requests by second, allowed for the given source.\n\nIt defaults to 0, which means no rate limiting.\n\nThe rate is actually defined by dividing average by period. So for a rate below 1 req/s, one needs to define a period larger than a second."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average: Option<RateLimitMiddlewareAverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<f64>,
    #[doc = "period, in combination with average, defines the actual maximum rate.\n\nIt defaults to 1 second."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<RateLimitMiddlewarePeriod>,
    #[serde(
        rename = "sourceCriterion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_criterion: Option<SourceCriterion>,
}
impl From<&RateLimitMiddleware> for RateLimitMiddleware {
    fn from(value: &RateLimitMiddleware) -> Self {
        value.clone()
    }
}
impl RateLimitMiddleware {
    pub fn builder() -> builder::RateLimitMiddleware {
        builder::RateLimitMiddleware::default()
    }
}
#[doc = "average is the maximum rate, by default in requests by second, allowed for the given source.\n\nIt defaults to 0, which means no rate limiting.\n\nThe rate is actually defined by dividing average by period. So for a rate below 1 req/s, one needs to define a period larger than a second."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RateLimitMiddlewareAverage {
    Variant0(String),
    Variant1(f64),
}
impl From<&RateLimitMiddlewareAverage> for RateLimitMiddlewareAverage {
    fn from(value: &RateLimitMiddlewareAverage) -> Self {
        value.clone()
    }
}
impl std::str::FromStr for RateLimitMiddlewareAverage {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, &'static str> {
        if let Ok(v) = value.parse() {
            Ok(Self::Variant0(v))
        } else if let Ok(v) = value.parse() {
            Ok(Self::Variant1(v))
        } else {
            Err("string conversion failed for all variants")
        }
    }
}
impl std::convert::TryFrom<&str> for RateLimitMiddlewareAverage {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, &'static str> {
        value.parse()
    }
}
impl std::convert::TryFrom<&String> for RateLimitMiddlewareAverage {
    type Error = &'static str;
    fn try_from(value: &String) -> Result<Self, &'static str> {
        value.parse()
    }
}
impl std::convert::TryFrom<String> for RateLimitMiddlewareAverage {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, &'static str> {
        value.parse()
    }
}
impl ToString for RateLimitMiddlewareAverage {
    fn to_string(&self) -> String {
        match self {
            Self::Variant0(x) => x.to_string(),
            Self::Variant1(x) => x.to_string(),
        }
    }
}
impl From<f64> for RateLimitMiddlewareAverage {
    fn from(value: f64) -> Self {
        Self::Variant1(value)
    }
}
#[doc = "period, in combination with average, defines the actual maximum rate.\n\nIt defaults to 1 second."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RateLimitMiddlewarePeriod {
    Variant0(String),
    Variant1(f64),
}
impl From<&RateLimitMiddlewarePeriod> for RateLimitMiddlewarePeriod {
    fn from(value: &RateLimitMiddlewarePeriod) -> Self {
        value.clone()
    }
}
impl std::str::FromStr for RateLimitMiddlewarePeriod {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, &'static str> {
        if let Ok(v) = value.parse() {
            Ok(Self::Variant0(v))
        } else if let Ok(v) = value.parse() {
            Ok(Self::Variant1(v))
        } else {
            Err("string conversion failed for all variants")
        }
    }
}
impl std::convert::TryFrom<&str> for RateLimitMiddlewarePeriod {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, &'static str> {
        value.parse()
    }
}
impl std::convert::TryFrom<&String> for RateLimitMiddlewarePeriod {
    type Error = &'static str;
    fn try_from(value: &String) -> Result<Self, &'static str> {
        value.parse()
    }
}
impl std::convert::TryFrom<String> for RateLimitMiddlewarePeriod {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, &'static str> {
        value.parse()
    }
}
impl ToString for RateLimitMiddlewarePeriod {
    fn to_string(&self) -> String {
        match self {
            Self::Variant0(x) => x.to_string(),
            Self::Variant1(x) => x.to_string(),
        }
    }
}
impl From<f64> for RateLimitMiddlewarePeriod {
    fn from(value: f64) -> Self {
        Self::Variant1(value)
    }
}
#[doc = "RegexRedirect redirect a request from an url to another with regex matching and replacement."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectRegexMiddleware {
    #[doc = "Set the permanent option to true to apply a permanent redirection."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permanent: Option<bool>,
    #[doc = "The regex option is the regular expression to match and capture elements from the request URL."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[doc = "The replacement option defines how to modify the URL to have the new target URL. Care should be taken when defining replacement expand variables: $1x is equivalent to ${1x}, not ${1}x (see Regexp.Expand), so use ${1} syntax."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}
impl From<&RedirectRegexMiddleware> for RedirectRegexMiddleware {
    fn from(value: &RedirectRegexMiddleware) -> Self {
        value.clone()
    }
}
impl RedirectRegexMiddleware {
    pub fn builder() -> builder::RedirectRegexMiddleware {
        builder::RedirectRegexMiddleware::default()
    }
}
#[doc = "RedirectScheme redirect request from a scheme to another."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectSchemeMiddleware {
    #[doc = "Set the permanent option to true to apply a permanent redirection."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permanent: Option<bool>,
    #[doc = "The port option defines the port of the new url. Port in this configuration is a string, not a numeric value."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[doc = "The scheme option defines the scheme of the new url."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}
impl From<&RedirectSchemeMiddleware> for RedirectSchemeMiddleware {
    fn from(value: &RedirectSchemeMiddleware) -> Self {
        value.clone()
    }
}
impl RedirectSchemeMiddleware {
    pub fn builder() -> builder::RedirectSchemeMiddleware {
        builder::RedirectSchemeMiddleware::default()
    }
}
#[doc = "Replace the path of the request url. It will replace the actual path by the specified one and will store the original path in a X-Replaced-Path header."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacePathMiddleware {
    #[doc = "The path option defines the path to use as replacement in the request url."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}
impl From<&ReplacePathMiddleware> for ReplacePathMiddleware {
    fn from(value: &ReplacePathMiddleware) -> Self {
        value.clone()
    }
}
impl ReplacePathMiddleware {
    pub fn builder() -> builder::ReplacePathMiddleware {
        builder::ReplacePathMiddleware::default()
    }
}
#[doc = "The ReplaceRegex replace a path from an url to another with regex matching and replacement. It will replace the actual path by the specified one and store the original path in a X-Replaced-Path header."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacePathRegexMiddleware {
    #[doc = "The regex option is the regular expression to match and capture the path from the request URL."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[doc = "The replacement option defines how to modify the path to have the new target path. Care should be taken when defining replacement expand variables: $1x is equivalent to ${1x}, not ${1}x (see Regexp.Expand), so use ${1} syntax."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}
impl From<&ReplacePathRegexMiddleware> for ReplacePathRegexMiddleware {
    fn from(value: &ReplacePathRegexMiddleware) -> Self {
        value.clone()
    }
}
impl ReplacePathRegexMiddleware {
    pub fn builder() -> builder::ReplacePathRegexMiddleware {
        builder::ReplacePathRegexMiddleware::default()
    }
}
#[doc = "The Retry middleware is in charge of reissuing a request a given number of times to a backend server if that server does not reply. To be clear, as soon as the server answers, the middleware stops retrying, regardless of the response status."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryMiddleware {
    #[doc = "The attempts option defines how many times the request should be retried."]
    pub attempts: i64,
    #[doc = "The initialInterval option defines the first wait time in the exponential backoff series."]
    #[serde(
        rename = "initialInterval",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub initial_interval: Option<String>,
}
impl From<&RetryMiddleware> for RetryMiddleware {
    fn from(value: &RetryMiddleware) -> Self {
        value.clone()
    }
}
impl RetryMiddleware {
    pub fn builder() -> builder::RetryMiddleware {
        builder::RetryMiddleware::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Root {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<RootHttp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<RootTcp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<RootTls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<RootUdp>,
}
impl From<&Root> for Root {
    fn from(value: &Root) -> Self {
        value.clone()
    }
}
impl Root {
    pub fn builder() -> builder::Root {
        builder::Root::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootHttp {
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub middlewares: std::collections::HashMap<String, HttpMiddleware>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub routers: std::collections::HashMap<String, HttpRouter>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub services: std::collections::HashMap<String, HttpService>,
}
impl From<&RootHttp> for RootHttp {
    fn from(value: &RootHttp) -> Self {
        value.clone()
    }
}
impl RootHttp {
    pub fn builder() -> builder::RootHttp {
        builder::RootHttp::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootTcp {
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub routers: std::collections::HashMap<String, TcpRouter>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub services: std::collections::HashMap<String, TcpService>,
}
impl From<&RootTcp> for RootTcp {
    fn from(value: &RootTcp) -> Self {
        value.clone()
    }
}
impl RootTcp {
    pub fn builder() -> builder::RootTcp {
        builder::RootTcp::default()
    }
}
#[doc = "Configures the TLS connection, TLS options, and certificate stores."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootTls {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<RootTlsCertificatesItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<RootTlsOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stores: Option<RootTlsStores>,
}
impl From<&RootTls> for RootTls {
    fn from(value: &RootTls) -> Self {
        value.clone()
    }
}
impl RootTls {
    pub fn builder() -> builder::RootTls {
        builder::RootTls::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootTlsCertificatesItem {
    #[serde(rename = "certFile", default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<String>,
    #[serde(rename = "keyFile", default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<String>,
    #[doc = "A list of stores can be specified here to indicate where the certificates should be stored. Although the stores list will actually be ignored and automatically set to [\"default\"]."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stores: Vec<String>,
}
impl From<&RootTlsCertificatesItem> for RootTlsCertificatesItem {
    fn from(value: &RootTlsCertificatesItem) -> Self {
        value.clone()
    }
}
impl RootTlsCertificatesItem {
    pub fn builder() -> builder::RootTlsCertificatesItem {
        builder::RootTlsCertificatesItem::default()
    }
}
#[doc = "The TLS options allow one to configure some parameters of the TLS connection."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootTlsOptions {}
impl From<&RootTlsOptions> for RootTlsOptions {
    fn from(value: &RootTlsOptions) -> Self {
        value.clone()
    }
}
impl RootTlsOptions {
    pub fn builder() -> builder::RootTlsOptions {
        builder::RootTlsOptions::default()
    }
}
#[doc = "Any store definition other than the default one (named default) will be ignored, and there is therefore only one globally available TLS store."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootTlsStores {}
impl From<&RootTlsStores> for RootTlsStores {
    fn from(value: &RootTlsStores) -> Self {
        value.clone()
    }
}
impl RootTlsStores {
    pub fn builder() -> builder::RootTlsStores {
        builder::RootTlsStores::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootUdp {
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub routers: std::collections::HashMap<String, UdpRouter>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub services: std::collections::HashMap<String, UdpService>,
}
impl From<&RootUdp> for RootUdp {
    fn from(value: &RootUdp) -> Self {
        value.clone()
    }
}
impl RootUdp {
    pub fn builder() -> builder::RootUdp {
        builder::RootUdp::default()
    }
}
#[doc = "SourceCriterion defines what criterion is used to group requests as originating from a common source. The precedence order is ipStrategy, then requestHeaderName, then requestHost. If none are set, the default is to use the requestHost."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCriterion {
    #[serde(
        rename = "ipStrategy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ip_strategy: Option<IpStrategy>,
    #[doc = "Requests having the same value for the given header are grouped as coming from the same source."]
    #[serde(
        rename = "requestHeaderName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_header_name: Option<String>,
    #[doc = "Whether to consider the request host as the source."]
    #[serde(
        rename = "requestHost",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_host: Option<bool>,
}
impl From<&SourceCriterion> for SourceCriterion {
    fn from(value: &SourceCriterion) -> Self {
        value.clone()
    }
}
impl SourceCriterion {
    pub fn builder() -> builder::SourceCriterion {
        builder::SourceCriterion::default()
    }
}
#[doc = "Remove the specified prefixes from the URL path. It will strip the matching path prefix and will store the matching path prefix in a X-Forwarded-Prefix header."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripPrefixMiddleware {
    #[doc = "The forceSlash option makes sure that the resulting stripped path is not the empty string, by replacing it with / when necessary.\n\nThis option was added to keep the initial (non-intuitive) behavior of this middleware, in order to avoid introducing a breaking change.\n\nIt's recommended to explicitly set forceSlash to false."]
    #[serde(
        rename = "forceSlash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub force_slash: Option<bool>,
    #[doc = "The prefixes option defines the prefixes to strip from the request URL"]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
}
impl From<&StripPrefixMiddleware> for StripPrefixMiddleware {
    fn from(value: &StripPrefixMiddleware) -> Self {
        value.clone()
    }
}
impl StripPrefixMiddleware {
    pub fn builder() -> builder::StripPrefixMiddleware {
        builder::StripPrefixMiddleware::default()
    }
}
#[doc = "Remove the matching prefixes from the URL path. It will strip the matching path prefix and will store the matching path prefix in a X-Forwarded-Prefix header."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripPrefixRegexMiddleware {
    #[doc = "The regex option is the regular expression to match the path prefix from the request URL."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regex: Vec<String>,
}
impl From<&StripPrefixRegexMiddleware> for StripPrefixRegexMiddleware {
    fn from(value: &StripPrefixRegexMiddleware) -> Self {
        value.clone()
    }
}
impl StripPrefixRegexMiddleware {
    pub fn builder() -> builder::StripPrefixRegexMiddleware {
        builder::StripPrefixRegexMiddleware::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpLoadBalancerService {
    #[serde(
        rename = "proxyProtocol",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub proxy_protocol: Option<TcpLoadBalancerServiceProxyProtocol>,
    #[doc = "Servers declare a single instance of your program."]
    pub servers: Vec<TcpLoadBalancerServiceServersItem>,
    #[serde(
        rename = "terminationDelay",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub termination_delay: Option<f64>,
}
impl From<&TcpLoadBalancerService> for TcpLoadBalancerService {
    fn from(value: &TcpLoadBalancerService) -> Self {
        value.clone()
    }
}
impl TcpLoadBalancerService {
    pub fn builder() -> builder::TcpLoadBalancerService {
        builder::TcpLoadBalancerService::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpLoadBalancerServiceProxyProtocol {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}
impl From<&TcpLoadBalancerServiceProxyProtocol> for TcpLoadBalancerServiceProxyProtocol {
    fn from(value: &TcpLoadBalancerServiceProxyProtocol) -> Self {
        value.clone()
    }
}
impl TcpLoadBalancerServiceProxyProtocol {
    pub fn builder() -> builder::TcpLoadBalancerServiceProxyProtocol {
        builder::TcpLoadBalancerServiceProxyProtocol::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpLoadBalancerServiceServersItem {
    #[doc = "The address option (IP:Port) point to a specific instance."]
    pub address: String,
}
impl From<&TcpLoadBalancerServiceServersItem> for TcpLoadBalancerServiceServersItem {
    fn from(value: &TcpLoadBalancerServiceServersItem) -> Self {
        value.clone()
    }
}
impl TcpLoadBalancerServiceServersItem {
    pub fn builder() -> builder::TcpLoadBalancerServiceServersItem {
        builder::TcpLoadBalancerServiceServersItem::default()
    }
}
#[doc = "If both HTTP routers and TCP routers listen to the same entry points, the TCP routers will apply before the HTTP routers. If no matching route is found for the TCP routers, then the HTTP routers will take over."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpRouter {
    #[doc = "If not specified, TCP routers will accept requests from all defined entry points. If you want to limit the router scope to a set of entry points, set the entry points option."]
    #[serde(rename = "entryPoints", default, skip_serializing_if = "Vec::is_empty")]
    pub entry_points: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub middlewares: Vec<String>,
    #[doc = "To avoid path overlap, routes are sorted, by default, in descending order using rules length. The priority is directly equal to the length of the rule, and so the longest length has the highest priority. A value of 0 for the priority is ignored: priority = 0 means that the default rules length sorting is used."]
    #[serde(default)]
    pub priority: u64,
    #[doc = "It is important to note that the Server Name Indication is an extension of the TLS protocol. Hence, only TLS routers will be able to specify a domain name with that rule. However, non-TLS routers will have to explicitly use that rule with * (every domain) to state that every non-TLS request will be handled by the router."]
    pub rule: String,
    #[doc = "You must attach a TCP service per TCP router. Services are the target for the router. TCP routers can only target TCP services (not HTTP services)."]
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TcpRouterTls>,
}
impl From<&TcpRouter> for TcpRouter {
    fn from(value: &TcpRouter) -> Self {
        value.clone()
    }
}
impl TcpRouter {
    pub fn builder() -> builder::TcpRouter {
        builder::TcpRouter::default()
    }
}
#[doc = "When a TLS section is specified, it instructs Traefik that the current router is dedicated to TLS requests only (and that the router should ignore non-TLS requests).\n\nBy default, a router with a TLS section will terminate the TLS connections, meaning that it will send decrypted data to the services."]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpRouterTls {
    #[doc = "If certResolver is defined, Traefik will try to generate certificates based on routers Host & HostSNI rules."]
    #[serde(
        rename = "certResolver",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cert_resolver: Option<String>,
    #[doc = "You can set SANs (alternative domains) for each main domain. Every domain must have A/AAAA records pointing to Traefik. Each domain & SAN will lead to a certificate request."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<TcpRouterTlsDomainsItem>,
    #[doc = "The options field enables fine-grained control of the TLS parameters. It refers to a TLS Options and will be applied only if a Host rule is defined."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
    #[doc = "A TLS router will terminate the TLS connection by default. However, the passthrough option can be specified to set whether the requests should be forwarded \"as is\", keeping all data encrypted."]
    #[serde(default)]
    pub passthrough: bool,
}
impl From<&TcpRouterTls> for TcpRouterTls {
    fn from(value: &TcpRouterTls) -> Self {
        value.clone()
    }
}
impl TcpRouterTls {
    pub fn builder() -> builder::TcpRouterTls {
        builder::TcpRouterTls::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpRouterTlsDomainsItem {
    #[doc = "Main defines the main domain name."]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    #[doc = "SANs defines the subject alternative domain names."]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
}
impl From<&TcpRouterTlsDomainsItem> for TcpRouterTlsDomainsItem {
    fn from(value: &TcpRouterTlsDomainsItem) -> Self {
        value.clone()
    }
}
impl TcpRouterTlsDomainsItem {
    pub fn builder() -> builder::TcpRouterTlsDomainsItem {
        builder::TcpRouterTlsDomainsItem::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum TcpService {
    Variant0 {
        #[serde(
            rename = "loadBalancer",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        load_balancer: Option<TcpLoadBalancerService>,
    },
    Variant1 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        weighted: Option<TcpWeightedService>,
    },
}
impl From<&TcpService> for TcpService {
    fn from(value: &TcpService) -> Self {
        value.clone()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpWeightedService {
    pub services: Vec<TcpWeightedServiceServicesItem>,
}
impl From<&TcpWeightedService> for TcpWeightedService {
    fn from(value: &TcpWeightedService) -> Self {
        value.clone()
    }
}
impl TcpWeightedService {
    pub fn builder() -> builder::TcpWeightedService {
        builder::TcpWeightedService::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpWeightedServiceServicesItem {
    pub name: String,
    pub weight: f64,
}
impl From<&TcpWeightedServiceServicesItem> for TcpWeightedServiceServicesItem {
    fn from(value: &TcpWeightedServiceServicesItem) -> Self {
        value.clone()
    }
}
impl TcpWeightedServiceServicesItem {
    pub fn builder() -> builder::TcpWeightedServiceServicesItem {
        builder::TcpWeightedServiceServicesItem::default()
    }
}
#[doc = "The servers load balancer is in charge of balancing the requests between the servers of the same service."]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpLoadBalancerService {
    #[doc = "The servers field defines all the servers that are part of this load-balancing group, i.e. each address (IP:Port) on which an instance of the service's program is deployed."]
    pub servers: Vec<UdpLoadBalancerServiceServersItem>,
}
impl From<&UdpLoadBalancerService> for UdpLoadBalancerService {
    fn from(value: &UdpLoadBalancerService) -> Self {
        value.clone()
    }
}
impl UdpLoadBalancerService {
    pub fn builder() -> builder::UdpLoadBalancerService {
        builder::UdpLoadBalancerService::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpLoadBalancerServiceServersItem {
    pub address: String,
}
impl From<&UdpLoadBalancerServiceServersItem> for UdpLoadBalancerServiceServersItem {
    fn from(value: &UdpLoadBalancerServiceServersItem) -> Self {
        value.clone()
    }
}
impl UdpLoadBalancerServiceServersItem {
    pub fn builder() -> builder::UdpLoadBalancerServiceServersItem {
        builder::UdpLoadBalancerServiceServersItem::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpRouter {
    #[doc = "If not specified, UDP routers will accept packets from all defined (UDP) entry points. If one wants to limit the router scope to a set of entry points, one should set the entry points option."]
    #[serde(rename = "entryPoints", default, skip_serializing_if = "Vec::is_empty")]
    pub entry_points: Vec<String>,
    #[doc = "There must be one (and only one) UDP service referenced per UDP router. Services are the target for the router."]
    pub service: String,
}
impl From<&UdpRouter> for UdpRouter {
    fn from(value: &UdpRouter) -> Self {
        value.clone()
    }
}
impl UdpRouter {
    pub fn builder() -> builder::UdpRouter {
        builder::UdpRouter::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum UdpService {
    Variant0 {
        #[serde(
            rename = "loadBalancer",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        load_balancer: Option<UdpLoadBalancerService>,
    },
    Variant1 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        weighted: Option<UdpWeightedService>,
    },
}
impl From<&UdpService> for UdpService {
    fn from(value: &UdpService) -> Self {
        value.clone()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpWeightedService {
    pub services: Vec<UdpWeightedServiceServicesItem>,
}
impl From<&UdpWeightedService> for UdpWeightedService {
    fn from(value: &UdpWeightedService) -> Self {
        value.clone()
    }
}
impl UdpWeightedService {
    pub fn builder() -> builder::UdpWeightedService {
        builder::UdpWeightedService::default()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpWeightedServiceServicesItem {
    pub name: String,
    pub weight: f64,
}
impl From<&UdpWeightedServiceServicesItem> for UdpWeightedServiceServicesItem {
    fn from(value: &UdpWeightedServiceServicesItem) -> Self {
        value.clone()
    }
}
impl UdpWeightedServiceServicesItem {
    pub fn builder() -> builder::UdpWeightedServiceServicesItem {
        builder::UdpWeightedServiceServicesItem::default()
    }
}
pub mod builder {
    #[derive(Clone, Debug)]
    pub struct AddPrefixMiddleware {
        prefix: Result<Option<String>, String>,
    }
    impl Default for AddPrefixMiddleware {
        fn default() -> Self {
            Self {
                prefix: Ok(Default::default()),
            }
        }
    }
    impl AddPrefixMiddleware {
        pub fn prefix<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.prefix = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for prefix: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<AddPrefixMiddleware> for super::AddPrefixMiddleware {
        type Error = String;
        fn try_from(value: AddPrefixMiddleware) -> Result<Self, String> {
            Ok(Self {
                prefix: value.prefix?,
            })
        }
    }
    impl From<super::AddPrefixMiddleware> for AddPrefixMiddleware {
        fn from(value: super::AddPrefixMiddleware) -> Self {
            Self {
                prefix: Ok(value.prefix),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct BasicAuthMiddleware {
        header_field: Result<Option<String>, String>,
        realm: Result<String, String>,
        remove_header: Result<bool, String>,
        users: Result<Vec<String>, String>,
        users_file: Result<Option<String>, String>,
    }
    impl Default for BasicAuthMiddleware {
        fn default() -> Self {
            Self {
                header_field: Ok(Default::default()),
                realm: Ok(super::defaults::basic_auth_middleware_realm()),
                remove_header: Ok(Default::default()),
                users: Ok(Default::default()),
                users_file: Ok(Default::default()),
            }
        }
    }
    impl BasicAuthMiddleware {
        pub fn header_field<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.header_field = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for header_field: {}", e));
            self
        }
        pub fn realm<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.realm = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for realm: {}", e));
            self
        }
        pub fn remove_header<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.remove_header = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for remove_header: {}", e));
            self
        }
        pub fn users<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.users = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for users: {}", e));
            self
        }
        pub fn users_file<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.users_file = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for users_file: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<BasicAuthMiddleware> for super::BasicAuthMiddleware {
        type Error = String;
        fn try_from(value: BasicAuthMiddleware) -> Result<Self, String> {
            Ok(Self {
                header_field: value.header_field?,
                realm: value.realm?,
                remove_header: value.remove_header?,
                users: value.users?,
                users_file: value.users_file?,
            })
        }
    }
    impl From<super::BasicAuthMiddleware> for BasicAuthMiddleware {
        fn from(value: super::BasicAuthMiddleware) -> Self {
            Self {
                header_field: Ok(value.header_field),
                realm: Ok(value.realm),
                remove_header: Ok(value.remove_header),
                users: Ok(value.users),
                users_file: Ok(value.users_file),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct BufferingMiddleware {
        max_request_body_bytes: Result<Option<i64>, String>,
        max_response_body_bytes: Result<Option<i64>, String>,
        mem_request_body_bytes: Result<Option<i64>, String>,
        mem_response_body_bytes: Result<Option<i64>, String>,
        retry_expression: Result<Option<String>, String>,
    }
    impl Default for BufferingMiddleware {
        fn default() -> Self {
            Self {
                max_request_body_bytes: Ok(Default::default()),
                max_response_body_bytes: Ok(Default::default()),
                mem_request_body_bytes: Ok(Default::default()),
                mem_response_body_bytes: Ok(Default::default()),
                retry_expression: Ok(Default::default()),
            }
        }
    }
    impl BufferingMiddleware {
        pub fn max_request_body_bytes<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.max_request_body_bytes = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for max_request_body_bytes: {}",
                    e
                )
            });
            self
        }
        pub fn max_response_body_bytes<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.max_response_body_bytes = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for max_response_body_bytes: {}",
                    e
                )
            });
            self
        }
        pub fn mem_request_body_bytes<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.mem_request_body_bytes = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for mem_request_body_bytes: {}",
                    e
                )
            });
            self
        }
        pub fn mem_response_body_bytes<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.mem_response_body_bytes = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for mem_response_body_bytes: {}",
                    e
                )
            });
            self
        }
        pub fn retry_expression<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.retry_expression = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for retry_expression: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<BufferingMiddleware> for super::BufferingMiddleware {
        type Error = String;
        fn try_from(value: BufferingMiddleware) -> Result<Self, String> {
            Ok(Self {
                max_request_body_bytes: value.max_request_body_bytes?,
                max_response_body_bytes: value.max_response_body_bytes?,
                mem_request_body_bytes: value.mem_request_body_bytes?,
                mem_response_body_bytes: value.mem_response_body_bytes?,
                retry_expression: value.retry_expression?,
            })
        }
    }
    impl From<super::BufferingMiddleware> for BufferingMiddleware {
        fn from(value: super::BufferingMiddleware) -> Self {
            Self {
                max_request_body_bytes: Ok(value.max_request_body_bytes),
                max_response_body_bytes: Ok(value.max_response_body_bytes),
                mem_request_body_bytes: Ok(value.mem_request_body_bytes),
                mem_response_body_bytes: Ok(value.mem_response_body_bytes),
                retry_expression: Ok(value.retry_expression),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ChainMiddleware {
        middlewares: Result<Vec<String>, String>,
    }
    impl Default for ChainMiddleware {
        fn default() -> Self {
            Self {
                middlewares: Ok(Default::default()),
            }
        }
    }
    impl ChainMiddleware {
        pub fn middlewares<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.middlewares = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for middlewares: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<ChainMiddleware> for super::ChainMiddleware {
        type Error = String;
        fn try_from(value: ChainMiddleware) -> Result<Self, String> {
            Ok(Self {
                middlewares: value.middlewares?,
            })
        }
    }
    impl From<super::ChainMiddleware> for ChainMiddleware {
        fn from(value: super::ChainMiddleware) -> Self {
            Self {
                middlewares: Ok(value.middlewares),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct CircuitBreakerMiddleware {
        check_period: Result<Option<String>, String>,
        expression: Result<Option<String>, String>,
        fallback_duration: Result<Option<String>, String>,
        recovery_duration: Result<Option<String>, String>,
    }
    impl Default for CircuitBreakerMiddleware {
        fn default() -> Self {
            Self {
                check_period: Ok(Default::default()),
                expression: Ok(Default::default()),
                fallback_duration: Ok(Default::default()),
                recovery_duration: Ok(Default::default()),
            }
        }
    }
    impl CircuitBreakerMiddleware {
        pub fn check_period<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.check_period = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for check_period: {}", e));
            self
        }
        pub fn expression<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.expression = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for expression: {}", e));
            self
        }
        pub fn fallback_duration<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.fallback_duration = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for fallback_duration: {}",
                    e
                )
            });
            self
        }
        pub fn recovery_duration<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.recovery_duration = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for recovery_duration: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<CircuitBreakerMiddleware> for super::CircuitBreakerMiddleware {
        type Error = String;
        fn try_from(value: CircuitBreakerMiddleware) -> Result<Self, String> {
            Ok(Self {
                check_period: value.check_period?,
                expression: value.expression?,
                fallback_duration: value.fallback_duration?,
                recovery_duration: value.recovery_duration?,
            })
        }
    }
    impl From<super::CircuitBreakerMiddleware> for CircuitBreakerMiddleware {
        fn from(value: super::CircuitBreakerMiddleware) -> Self {
            Self {
                check_period: Ok(value.check_period),
                expression: Ok(value.expression),
                fallback_duration: Ok(value.fallback_duration),
                recovery_duration: Ok(value.recovery_duration),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct CompressMiddleware {
        excluded_content_types: Result<Vec<String>, String>,
        min_response_body_bytes: Result<Option<i64>, String>,
    }
    impl Default for CompressMiddleware {
        fn default() -> Self {
            Self {
                excluded_content_types: Ok(Default::default()),
                min_response_body_bytes: Ok(Default::default()),
            }
        }
    }
    impl CompressMiddleware {
        pub fn excluded_content_types<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.excluded_content_types = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for excluded_content_types: {}",
                    e
                )
            });
            self
        }
        pub fn min_response_body_bytes<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.min_response_body_bytes = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for min_response_body_bytes: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<CompressMiddleware> for super::CompressMiddleware {
        type Error = String;
        fn try_from(value: CompressMiddleware) -> Result<Self, String> {
            Ok(Self {
                excluded_content_types: value.excluded_content_types?,
                min_response_body_bytes: value.min_response_body_bytes?,
            })
        }
    }
    impl From<super::CompressMiddleware> for CompressMiddleware {
        fn from(value: super::CompressMiddleware) -> Self {
            Self {
                excluded_content_types: Ok(value.excluded_content_types),
                min_response_body_bytes: Ok(value.min_response_body_bytes),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ContentTypeMiddleware {
        auto_detect: Result<bool, String>,
    }
    impl Default for ContentTypeMiddleware {
        fn default() -> Self {
            Self {
                auto_detect: Ok(Default::default()),
            }
        }
    }
    impl ContentTypeMiddleware {
        pub fn auto_detect<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.auto_detect = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for auto_detect: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<ContentTypeMiddleware> for super::ContentTypeMiddleware {
        type Error = String;
        fn try_from(value: ContentTypeMiddleware) -> Result<Self, String> {
            Ok(Self {
                auto_detect: value.auto_detect?,
            })
        }
    }
    impl From<super::ContentTypeMiddleware> for ContentTypeMiddleware {
        fn from(value: super::ContentTypeMiddleware) -> Self {
            Self {
                auto_detect: Ok(value.auto_detect),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct DigestAuthMiddleware {
        header_field: Result<Option<String>, String>,
        realm: Result<String, String>,
        remove_header: Result<bool, String>,
        users: Result<Vec<String>, String>,
        users_file: Result<Option<String>, String>,
    }
    impl Default for DigestAuthMiddleware {
        fn default() -> Self {
            Self {
                header_field: Ok(Default::default()),
                realm: Ok(super::defaults::digest_auth_middleware_realm()),
                remove_header: Ok(Default::default()),
                users: Ok(Default::default()),
                users_file: Ok(Default::default()),
            }
        }
    }
    impl DigestAuthMiddleware {
        pub fn header_field<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.header_field = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for header_field: {}", e));
            self
        }
        pub fn realm<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.realm = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for realm: {}", e));
            self
        }
        pub fn remove_header<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.remove_header = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for remove_header: {}", e));
            self
        }
        pub fn users<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.users = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for users: {}", e));
            self
        }
        pub fn users_file<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.users_file = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for users_file: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<DigestAuthMiddleware> for super::DigestAuthMiddleware {
        type Error = String;
        fn try_from(value: DigestAuthMiddleware) -> Result<Self, String> {
            Ok(Self {
                header_field: value.header_field?,
                realm: value.realm?,
                remove_header: value.remove_header?,
                users: value.users?,
                users_file: value.users_file?,
            })
        }
    }
    impl From<super::DigestAuthMiddleware> for DigestAuthMiddleware {
        fn from(value: super::DigestAuthMiddleware) -> Self {
            Self {
                header_field: Ok(value.header_field),
                realm: Ok(value.realm),
                remove_header: Ok(value.remove_header),
                users: Ok(value.users),
                users_file: Ok(value.users_file),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ErrorsMiddleware {
        query: Result<Option<String>, String>,
        service: Result<Option<String>, String>,
        status: Result<Vec<String>, String>,
    }
    impl Default for ErrorsMiddleware {
        fn default() -> Self {
            Self {
                query: Ok(Default::default()),
                service: Ok(Default::default()),
                status: Ok(Default::default()),
            }
        }
    }
    impl ErrorsMiddleware {
        pub fn query<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.query = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for query: {}", e));
            self
        }
        pub fn service<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.service = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for service: {}", e));
            self
        }
        pub fn status<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.status = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for status: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<ErrorsMiddleware> for super::ErrorsMiddleware {
        type Error = String;
        fn try_from(value: ErrorsMiddleware) -> Result<Self, String> {
            Ok(Self {
                query: value.query?,
                service: value.service?,
                status: value.status?,
            })
        }
    }
    impl From<super::ErrorsMiddleware> for ErrorsMiddleware {
        fn from(value: super::ErrorsMiddleware) -> Self {
            Self {
                query: Ok(value.query),
                service: Ok(value.service),
                status: Ok(value.status),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ForwardAuthMiddleware {
        address: Result<Option<String>, String>,
        auth_request_headers: Result<Vec<String>, String>,
        auth_response_headers: Result<Vec<String>, String>,
        auth_response_headers_regex: Result<Option<String>, String>,
        tls: Result<Option<super::ForwardAuthMiddlewareTls>, String>,
        trust_forward_header: Result<Option<bool>, String>,
    }
    impl Default for ForwardAuthMiddleware {
        fn default() -> Self {
            Self {
                address: Ok(Default::default()),
                auth_request_headers: Ok(Default::default()),
                auth_response_headers: Ok(Default::default()),
                auth_response_headers_regex: Ok(Default::default()),
                tls: Ok(Default::default()),
                trust_forward_header: Ok(Default::default()),
            }
        }
    }
    impl ForwardAuthMiddleware {
        pub fn address<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.address = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for address: {}", e));
            self
        }
        pub fn auth_request_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.auth_request_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for auth_request_headers: {}",
                    e
                )
            });
            self
        }
        pub fn auth_response_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.auth_response_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for auth_response_headers: {}",
                    e
                )
            });
            self
        }
        pub fn auth_response_headers_regex<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.auth_response_headers_regex = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for auth_response_headers_regex: {}",
                    e
                )
            });
            self
        }
        pub fn tls<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::ForwardAuthMiddlewareTls>>,
            T::Error: std::fmt::Display,
        {
            self.tls = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for tls: {}", e));
            self
        }
        pub fn trust_forward_header<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.trust_forward_header = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for trust_forward_header: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<ForwardAuthMiddleware> for super::ForwardAuthMiddleware {
        type Error = String;
        fn try_from(value: ForwardAuthMiddleware) -> Result<Self, String> {
            Ok(Self {
                address: value.address?,
                auth_request_headers: value.auth_request_headers?,
                auth_response_headers: value.auth_response_headers?,
                auth_response_headers_regex: value.auth_response_headers_regex?,
                tls: value.tls?,
                trust_forward_header: value.trust_forward_header?,
            })
        }
    }
    impl From<super::ForwardAuthMiddleware> for ForwardAuthMiddleware {
        fn from(value: super::ForwardAuthMiddleware) -> Self {
            Self {
                address: Ok(value.address),
                auth_request_headers: Ok(value.auth_request_headers),
                auth_response_headers: Ok(value.auth_response_headers),
                auth_response_headers_regex: Ok(value.auth_response_headers_regex),
                tls: Ok(value.tls),
                trust_forward_header: Ok(value.trust_forward_header),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ForwardAuthMiddlewareTls {
        ca: Result<Option<String>, String>,
        ca_optional: Result<Option<bool>, String>,
        cert: Result<Option<String>, String>,
        insecure_skip_verify: Result<Option<bool>, String>,
        key: Result<Option<String>, String>,
    }
    impl Default for ForwardAuthMiddlewareTls {
        fn default() -> Self {
            Self {
                ca: Ok(Default::default()),
                ca_optional: Ok(Default::default()),
                cert: Ok(Default::default()),
                insecure_skip_verify: Ok(Default::default()),
                key: Ok(Default::default()),
            }
        }
    }
    impl ForwardAuthMiddlewareTls {
        pub fn ca<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.ca = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ca: {}", e));
            self
        }
        pub fn ca_optional<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.ca_optional = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ca_optional: {}", e));
            self
        }
        pub fn cert<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.cert = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for cert: {}", e));
            self
        }
        pub fn insecure_skip_verify<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.insecure_skip_verify = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for insecure_skip_verify: {}",
                    e
                )
            });
            self
        }
        pub fn key<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.key = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for key: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<ForwardAuthMiddlewareTls> for super::ForwardAuthMiddlewareTls {
        type Error = String;
        fn try_from(value: ForwardAuthMiddlewareTls) -> Result<Self, String> {
            Ok(Self {
                ca: value.ca?,
                ca_optional: value.ca_optional?,
                cert: value.cert?,
                insecure_skip_verify: value.insecure_skip_verify?,
                key: value.key?,
            })
        }
    }
    impl From<super::ForwardAuthMiddlewareTls> for ForwardAuthMiddlewareTls {
        fn from(value: super::ForwardAuthMiddlewareTls) -> Self {
            Self {
                ca: Ok(value.ca),
                ca_optional: Ok(value.ca_optional),
                cert: Ok(value.cert),
                insecure_skip_verify: Ok(value.insecure_skip_verify),
                key: Ok(value.key),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HeadersMiddleware {
        access_control_allow_credentials: Result<Option<bool>, String>,
        access_control_allow_headers: Result<Vec<String>, String>,
        access_control_allow_methods: Result<Vec<String>, String>,
        access_control_allow_origin_list: Result<Vec<String>, String>,
        access_control_allow_origin_list_regex: Result<Vec<String>, String>,
        access_control_expose_headers: Result<Vec<String>, String>,
        access_control_max_age: Result<Option<i64>, String>,
        add_vary_header: Result<Option<bool>, String>,
        allowed_hosts: Result<Vec<String>, String>,
        browser_xss_filter: Result<Option<bool>, String>,
        content_security_policy: Result<Option<String>, String>,
        content_type_nosniff: Result<Option<bool>, String>,
        custom_browser_xss_value: Result<Option<String>, String>,
        custom_frame_options_value: Result<Option<String>, String>,
        custom_request_headers: Result<std::collections::HashMap<String, String>, String>,
        custom_response_headers: Result<std::collections::HashMap<String, String>, String>,
        feature_policy: Result<Option<String>, String>,
        force_sts_header: Result<Option<bool>, String>,
        frame_deny: Result<Option<bool>, String>,
        hosts_proxy_headers: Result<Vec<String>, String>,
        is_development: Result<Option<bool>, String>,
        permissions_policy: Result<Option<String>, String>,
        public_key: Result<Option<String>, String>,
        referrer_policy: Result<Option<String>, String>,
        ssl_force_host: Result<Option<bool>, String>,
        ssl_host: Result<Option<String>, String>,
        ssl_proxy_headers: Result<std::collections::HashMap<String, String>, String>,
        ssl_redirect: Result<Option<bool>, String>,
        ssl_temporary_redirect: Result<Option<bool>, String>,
        sts_include_subdomains: Result<Option<bool>, String>,
        sts_preload: Result<Option<bool>, String>,
        sts_seconds: Result<Option<i64>, String>,
    }
    impl Default for HeadersMiddleware {
        fn default() -> Self {
            Self {
                access_control_allow_credentials: Ok(Default::default()),
                access_control_allow_headers: Ok(Default::default()),
                access_control_allow_methods: Ok(Default::default()),
                access_control_allow_origin_list: Ok(Default::default()),
                access_control_allow_origin_list_regex: Ok(Default::default()),
                access_control_expose_headers: Ok(Default::default()),
                access_control_max_age: Ok(Default::default()),
                add_vary_header: Ok(Default::default()),
                allowed_hosts: Ok(Default::default()),
                browser_xss_filter: Ok(Default::default()),
                content_security_policy: Ok(Default::default()),
                content_type_nosniff: Ok(Default::default()),
                custom_browser_xss_value: Ok(Default::default()),
                custom_frame_options_value: Ok(Default::default()),
                custom_request_headers: Ok(Default::default()),
                custom_response_headers: Ok(Default::default()),
                feature_policy: Ok(Default::default()),
                force_sts_header: Ok(Default::default()),
                frame_deny: Ok(Default::default()),
                hosts_proxy_headers: Ok(Default::default()),
                is_development: Ok(Default::default()),
                permissions_policy: Ok(Default::default()),
                public_key: Ok(Default::default()),
                referrer_policy: Ok(Default::default()),
                ssl_force_host: Ok(Default::default()),
                ssl_host: Ok(Default::default()),
                ssl_proxy_headers: Ok(Default::default()),
                ssl_redirect: Ok(Default::default()),
                ssl_temporary_redirect: Ok(Default::default()),
                sts_include_subdomains: Ok(Default::default()),
                sts_preload: Ok(Default::default()),
                sts_seconds: Ok(Default::default()),
            }
        }
    }
    impl HeadersMiddleware {
        pub fn access_control_allow_credentials<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.access_control_allow_credentials = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for access_control_allow_credentials: {}",
                    e
                )
            });
            self
        }
        pub fn access_control_allow_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.access_control_allow_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for access_control_allow_headers: {}",
                    e
                )
            });
            self
        }
        pub fn access_control_allow_methods<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.access_control_allow_methods = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for access_control_allow_methods: {}",
                    e
                )
            });
            self
        }
        pub fn access_control_allow_origin_list<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.access_control_allow_origin_list = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for access_control_allow_origin_list: {}",
                    e
                )
            });
            self
        }
        pub fn access_control_allow_origin_list_regex<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self . access_control_allow_origin_list_regex = value . try_into () . map_err (| e | format ! ("error converting supplied value for access_control_allow_origin_list_regex: {}" , e)) ;
            self
        }
        pub fn access_control_expose_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.access_control_expose_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for access_control_expose_headers: {}",
                    e
                )
            });
            self
        }
        pub fn access_control_max_age<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.access_control_max_age = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for access_control_max_age: {}",
                    e
                )
            });
            self
        }
        pub fn add_vary_header<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.add_vary_header = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for add_vary_header: {}", e));
            self
        }
        pub fn allowed_hosts<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.allowed_hosts = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for allowed_hosts: {}", e));
            self
        }
        pub fn browser_xss_filter<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.browser_xss_filter = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for browser_xss_filter: {}",
                    e
                )
            });
            self
        }
        pub fn content_security_policy<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.content_security_policy = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for content_security_policy: {}",
                    e
                )
            });
            self
        }
        pub fn content_type_nosniff<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.content_type_nosniff = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for content_type_nosniff: {}",
                    e
                )
            });
            self
        }
        pub fn custom_browser_xss_value<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.custom_browser_xss_value = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for custom_browser_xss_value: {}",
                    e
                )
            });
            self
        }
        pub fn custom_frame_options_value<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.custom_frame_options_value = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for custom_frame_options_value: {}",
                    e
                )
            });
            self
        }
        pub fn custom_request_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, String>>,
            T::Error: std::fmt::Display,
        {
            self.custom_request_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for custom_request_headers: {}",
                    e
                )
            });
            self
        }
        pub fn custom_response_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, String>>,
            T::Error: std::fmt::Display,
        {
            self.custom_response_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for custom_response_headers: {}",
                    e
                )
            });
            self
        }
        pub fn feature_policy<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.feature_policy = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for feature_policy: {}", e));
            self
        }
        pub fn force_sts_header<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.force_sts_header = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for force_sts_header: {}",
                    e
                )
            });
            self
        }
        pub fn frame_deny<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.frame_deny = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for frame_deny: {}", e));
            self
        }
        pub fn hosts_proxy_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.hosts_proxy_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for hosts_proxy_headers: {}",
                    e
                )
            });
            self
        }
        pub fn is_development<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.is_development = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for is_development: {}", e));
            self
        }
        pub fn permissions_policy<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.permissions_policy = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for permissions_policy: {}",
                    e
                )
            });
            self
        }
        pub fn public_key<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.public_key = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for public_key: {}", e));
            self
        }
        pub fn referrer_policy<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.referrer_policy = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for referrer_policy: {}", e));
            self
        }
        pub fn ssl_force_host<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.ssl_force_host = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ssl_force_host: {}", e));
            self
        }
        pub fn ssl_host<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.ssl_host = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ssl_host: {}", e));
            self
        }
        pub fn ssl_proxy_headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, String>>,
            T::Error: std::fmt::Display,
        {
            self.ssl_proxy_headers = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for ssl_proxy_headers: {}",
                    e
                )
            });
            self
        }
        pub fn ssl_redirect<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.ssl_redirect = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ssl_redirect: {}", e));
            self
        }
        pub fn ssl_temporary_redirect<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.ssl_temporary_redirect = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for ssl_temporary_redirect: {}",
                    e
                )
            });
            self
        }
        pub fn sts_include_subdomains<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.sts_include_subdomains = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for sts_include_subdomains: {}",
                    e
                )
            });
            self
        }
        pub fn sts_preload<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.sts_preload = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sts_preload: {}", e));
            self
        }
        pub fn sts_seconds<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.sts_seconds = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sts_seconds: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HeadersMiddleware> for super::HeadersMiddleware {
        type Error = String;
        fn try_from(value: HeadersMiddleware) -> Result<Self, String> {
            Ok(Self {
                access_control_allow_credentials: value.access_control_allow_credentials?,
                access_control_allow_headers: value.access_control_allow_headers?,
                access_control_allow_methods: value.access_control_allow_methods?,
                access_control_allow_origin_list: value.access_control_allow_origin_list?,
                access_control_allow_origin_list_regex: value
                    .access_control_allow_origin_list_regex?,
                access_control_expose_headers: value.access_control_expose_headers?,
                access_control_max_age: value.access_control_max_age?,
                add_vary_header: value.add_vary_header?,
                allowed_hosts: value.allowed_hosts?,
                browser_xss_filter: value.browser_xss_filter?,
                content_security_policy: value.content_security_policy?,
                content_type_nosniff: value.content_type_nosniff?,
                custom_browser_xss_value: value.custom_browser_xss_value?,
                custom_frame_options_value: value.custom_frame_options_value?,
                custom_request_headers: value.custom_request_headers?,
                custom_response_headers: value.custom_response_headers?,
                feature_policy: value.feature_policy?,
                force_sts_header: value.force_sts_header?,
                frame_deny: value.frame_deny?,
                hosts_proxy_headers: value.hosts_proxy_headers?,
                is_development: value.is_development?,
                permissions_policy: value.permissions_policy?,
                public_key: value.public_key?,
                referrer_policy: value.referrer_policy?,
                ssl_force_host: value.ssl_force_host?,
                ssl_host: value.ssl_host?,
                ssl_proxy_headers: value.ssl_proxy_headers?,
                ssl_redirect: value.ssl_redirect?,
                ssl_temporary_redirect: value.ssl_temporary_redirect?,
                sts_include_subdomains: value.sts_include_subdomains?,
                sts_preload: value.sts_preload?,
                sts_seconds: value.sts_seconds?,
            })
        }
    }
    impl From<super::HeadersMiddleware> for HeadersMiddleware {
        fn from(value: super::HeadersMiddleware) -> Self {
            Self {
                access_control_allow_credentials: Ok(value.access_control_allow_credentials),
                access_control_allow_headers: Ok(value.access_control_allow_headers),
                access_control_allow_methods: Ok(value.access_control_allow_methods),
                access_control_allow_origin_list: Ok(value.access_control_allow_origin_list),
                access_control_allow_origin_list_regex: Ok(
                    value.access_control_allow_origin_list_regex
                ),
                access_control_expose_headers: Ok(value.access_control_expose_headers),
                access_control_max_age: Ok(value.access_control_max_age),
                add_vary_header: Ok(value.add_vary_header),
                allowed_hosts: Ok(value.allowed_hosts),
                browser_xss_filter: Ok(value.browser_xss_filter),
                content_security_policy: Ok(value.content_security_policy),
                content_type_nosniff: Ok(value.content_type_nosniff),
                custom_browser_xss_value: Ok(value.custom_browser_xss_value),
                custom_frame_options_value: Ok(value.custom_frame_options_value),
                custom_request_headers: Ok(value.custom_request_headers),
                custom_response_headers: Ok(value.custom_response_headers),
                feature_policy: Ok(value.feature_policy),
                force_sts_header: Ok(value.force_sts_header),
                frame_deny: Ok(value.frame_deny),
                hosts_proxy_headers: Ok(value.hosts_proxy_headers),
                is_development: Ok(value.is_development),
                permissions_policy: Ok(value.permissions_policy),
                public_key: Ok(value.public_key),
                referrer_policy: Ok(value.referrer_policy),
                ssl_force_host: Ok(value.ssl_force_host),
                ssl_host: Ok(value.ssl_host),
                ssl_proxy_headers: Ok(value.ssl_proxy_headers),
                ssl_redirect: Ok(value.ssl_redirect),
                ssl_temporary_redirect: Ok(value.ssl_temporary_redirect),
                sts_include_subdomains: Ok(value.sts_include_subdomains),
                sts_preload: Ok(value.sts_preload),
                sts_seconds: Ok(value.sts_seconds),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpFailoverService {
        fallback: Result<Option<String>, String>,
        health_check: Result<serde_json::Map<String, serde_json::Value>, String>,
        service: Result<Option<String>, String>,
    }
    impl Default for HttpFailoverService {
        fn default() -> Self {
            Self {
                fallback: Ok(Default::default()),
                health_check: Ok(Default::default()),
                service: Ok(Default::default()),
            }
        }
    }
    impl HttpFailoverService {
        pub fn fallback<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.fallback = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for fallback: {}", e));
            self
        }
        pub fn health_check<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<serde_json::Map<String, serde_json::Value>>,
            T::Error: std::fmt::Display,
        {
            self.health_check = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for health_check: {}", e));
            self
        }
        pub fn service<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.service = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for service: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpFailoverService> for super::HttpFailoverService {
        type Error = String;
        fn try_from(value: HttpFailoverService) -> Result<Self, String> {
            Ok(Self {
                fallback: value.fallback?,
                health_check: value.health_check?,
                service: value.service?,
            })
        }
    }
    impl From<super::HttpFailoverService> for HttpFailoverService {
        fn from(value: super::HttpFailoverService) -> Self {
            Self {
                fallback: Ok(value.fallback),
                health_check: Ok(value.health_check),
                service: Ok(value.service),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpLoadBalancerService {
        health_check: Result<Option<super::HttpLoadBalancerServiceHealthCheck>, String>,
        pass_host_header: Result<bool, String>,
        response_forwarding:
            Result<Option<super::HttpLoadBalancerServiceResponseForwarding>, String>,
        servers: Result<Vec<super::HttpLoadBalancerServiceServersItem>, String>,
        servers_transport: Result<Option<String>, String>,
        sticky: Result<Option<super::HttpLoadBalancerServiceSticky>, String>,
    }
    impl Default for HttpLoadBalancerService {
        fn default() -> Self {
            Self {
                health_check: Ok(Default::default()),
                pass_host_header: Ok(super::defaults::default_bool::<true>()),
                response_forwarding: Ok(Default::default()),
                servers: Err("no value supplied for servers".to_string()),
                servers_transport: Ok(Default::default()),
                sticky: Ok(Default::default()),
            }
        }
    }
    impl HttpLoadBalancerService {
        pub fn health_check<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpLoadBalancerServiceHealthCheck>>,
            T::Error: std::fmt::Display,
        {
            self.health_check = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for health_check: {}", e));
            self
        }
        pub fn pass_host_header<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.pass_host_header = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for pass_host_header: {}",
                    e
                )
            });
            self
        }
        pub fn response_forwarding<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpLoadBalancerServiceResponseForwarding>>,
            T::Error: std::fmt::Display,
        {
            self.response_forwarding = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for response_forwarding: {}",
                    e
                )
            });
            self
        }
        pub fn servers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::HttpLoadBalancerServiceServersItem>>,
            T::Error: std::fmt::Display,
        {
            self.servers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for servers: {}", e));
            self
        }
        pub fn servers_transport<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.servers_transport = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for servers_transport: {}",
                    e
                )
            });
            self
        }
        pub fn sticky<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpLoadBalancerServiceSticky>>,
            T::Error: std::fmt::Display,
        {
            self.sticky = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sticky: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpLoadBalancerService> for super::HttpLoadBalancerService {
        type Error = String;
        fn try_from(value: HttpLoadBalancerService) -> Result<Self, String> {
            Ok(Self {
                health_check: value.health_check?,
                pass_host_header: value.pass_host_header?,
                response_forwarding: value.response_forwarding?,
                servers: value.servers?,
                servers_transport: value.servers_transport?,
                sticky: value.sticky?,
            })
        }
    }
    impl From<super::HttpLoadBalancerService> for HttpLoadBalancerService {
        fn from(value: super::HttpLoadBalancerService) -> Self {
            Self {
                health_check: Ok(value.health_check),
                pass_host_header: Ok(value.pass_host_header),
                response_forwarding: Ok(value.response_forwarding),
                servers: Ok(value.servers),
                servers_transport: Ok(value.servers_transport),
                sticky: Ok(value.sticky),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpLoadBalancerServiceHealthCheck {
        follow_redirects: Result<bool, String>,
        headers: Result<std::collections::HashMap<String, String>, String>,
        hostname: Result<Option<String>, String>,
        interval: Result<Option<String>, String>,
        method: Result<Option<String>, String>,
        path: Result<Option<String>, String>,
        port: Result<Option<i64>, String>,
        scheme: Result<Option<String>, String>,
        timeout: Result<Option<String>, String>,
    }
    impl Default for HttpLoadBalancerServiceHealthCheck {
        fn default() -> Self {
            Self {
                follow_redirects: Ok(super::defaults::default_bool::<true>()),
                headers: Ok(Default::default()),
                hostname: Ok(Default::default()),
                interval: Ok(Default::default()),
                method: Ok(Default::default()),
                path: Ok(Default::default()),
                port: Ok(Default::default()),
                scheme: Ok(Default::default()),
                timeout: Ok(Default::default()),
            }
        }
    }
    impl HttpLoadBalancerServiceHealthCheck {
        pub fn follow_redirects<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.follow_redirects = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for follow_redirects: {}",
                    e
                )
            });
            self
        }
        pub fn headers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, String>>,
            T::Error: std::fmt::Display,
        {
            self.headers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for headers: {}", e));
            self
        }
        pub fn hostname<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.hostname = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for hostname: {}", e));
            self
        }
        pub fn interval<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.interval = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for interval: {}", e));
            self
        }
        pub fn method<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.method = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for method: {}", e));
            self
        }
        pub fn path<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.path = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for path: {}", e));
            self
        }
        pub fn port<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.port = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for port: {}", e));
            self
        }
        pub fn scheme<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.scheme = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for scheme: {}", e));
            self
        }
        pub fn timeout<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.timeout = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for timeout: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpLoadBalancerServiceHealthCheck>
        for super::HttpLoadBalancerServiceHealthCheck
    {
        type Error = String;
        fn try_from(value: HttpLoadBalancerServiceHealthCheck) -> Result<Self, String> {
            Ok(Self {
                follow_redirects: value.follow_redirects?,
                headers: value.headers?,
                hostname: value.hostname?,
                interval: value.interval?,
                method: value.method?,
                path: value.path?,
                port: value.port?,
                scheme: value.scheme?,
                timeout: value.timeout?,
            })
        }
    }
    impl From<super::HttpLoadBalancerServiceHealthCheck> for HttpLoadBalancerServiceHealthCheck {
        fn from(value: super::HttpLoadBalancerServiceHealthCheck) -> Self {
            Self {
                follow_redirects: Ok(value.follow_redirects),
                headers: Ok(value.headers),
                hostname: Ok(value.hostname),
                interval: Ok(value.interval),
                method: Ok(value.method),
                path: Ok(value.path),
                port: Ok(value.port),
                scheme: Ok(value.scheme),
                timeout: Ok(value.timeout),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpLoadBalancerServiceResponseForwarding {
        flush_interval: Result<Option<String>, String>,
    }
    impl Default for HttpLoadBalancerServiceResponseForwarding {
        fn default() -> Self {
            Self {
                flush_interval: Ok(Default::default()),
            }
        }
    }
    impl HttpLoadBalancerServiceResponseForwarding {
        pub fn flush_interval<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.flush_interval = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for flush_interval: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpLoadBalancerServiceResponseForwarding>
        for super::HttpLoadBalancerServiceResponseForwarding
    {
        type Error = String;
        fn try_from(value: HttpLoadBalancerServiceResponseForwarding) -> Result<Self, String> {
            Ok(Self {
                flush_interval: value.flush_interval?,
            })
        }
    }
    impl From<super::HttpLoadBalancerServiceResponseForwarding>
        for HttpLoadBalancerServiceResponseForwarding
    {
        fn from(value: super::HttpLoadBalancerServiceResponseForwarding) -> Self {
            Self {
                flush_interval: Ok(value.flush_interval),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpLoadBalancerServiceServersItem {
        url: Result<String, String>,
    }
    impl Default for HttpLoadBalancerServiceServersItem {
        fn default() -> Self {
            Self {
                url: Err("no value supplied for url".to_string()),
            }
        }
    }
    impl HttpLoadBalancerServiceServersItem {
        pub fn url<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.url = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for url: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpLoadBalancerServiceServersItem>
        for super::HttpLoadBalancerServiceServersItem
    {
        type Error = String;
        fn try_from(value: HttpLoadBalancerServiceServersItem) -> Result<Self, String> {
            Ok(Self { url: value.url? })
        }
    }
    impl From<super::HttpLoadBalancerServiceServersItem> for HttpLoadBalancerServiceServersItem {
        fn from(value: super::HttpLoadBalancerServiceServersItem) -> Self {
            Self { url: Ok(value.url) }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpLoadBalancerServiceSticky {
        cookie: Result<Option<super::HttpLoadBalancerServiceStickyCookie>, String>,
    }
    impl Default for HttpLoadBalancerServiceSticky {
        fn default() -> Self {
            Self {
                cookie: Ok(Default::default()),
            }
        }
    }
    impl HttpLoadBalancerServiceSticky {
        pub fn cookie<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpLoadBalancerServiceStickyCookie>>,
            T::Error: std::fmt::Display,
        {
            self.cookie = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for cookie: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpLoadBalancerServiceSticky> for super::HttpLoadBalancerServiceSticky {
        type Error = String;
        fn try_from(value: HttpLoadBalancerServiceSticky) -> Result<Self, String> {
            Ok(Self {
                cookie: value.cookie?,
            })
        }
    }
    impl From<super::HttpLoadBalancerServiceSticky> for HttpLoadBalancerServiceSticky {
        fn from(value: super::HttpLoadBalancerServiceSticky) -> Self {
            Self {
                cookie: Ok(value.cookie),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpLoadBalancerServiceStickyCookie {
        http_only: Result<bool, String>,
        name: Result<Option<String>, String>,
        same_site: Result<String, String>,
        secure: Result<bool, String>,
    }
    impl Default for HttpLoadBalancerServiceStickyCookie {
        fn default() -> Self {
            Self {
                http_only: Ok(Default::default()),
                name: Ok(Default::default()),
                same_site: Ok(Default::default()),
                secure: Ok(Default::default()),
            }
        }
    }
    impl HttpLoadBalancerServiceStickyCookie {
        pub fn http_only<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.http_only = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for http_only: {}", e));
            self
        }
        pub fn name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for name: {}", e));
            self
        }
        pub fn same_site<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.same_site = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for same_site: {}", e));
            self
        }
        pub fn secure<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.secure = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for secure: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpLoadBalancerServiceStickyCookie>
        for super::HttpLoadBalancerServiceStickyCookie
    {
        type Error = String;
        fn try_from(value: HttpLoadBalancerServiceStickyCookie) -> Result<Self, String> {
            Ok(Self {
                http_only: value.http_only?,
                name: value.name?,
                same_site: value.same_site?,
                secure: value.secure?,
            })
        }
    }
    impl From<super::HttpLoadBalancerServiceStickyCookie> for HttpLoadBalancerServiceStickyCookie {
        fn from(value: super::HttpLoadBalancerServiceStickyCookie) -> Self {
            Self {
                http_only: Ok(value.http_only),
                name: Ok(value.name),
                same_site: Ok(value.same_site),
                secure: Ok(value.secure),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpMirroringService {
        health_check: Result<serde_json::Map<String, serde_json::Value>, String>,
        max_body_size: Result<i64, String>,
        mirrors: Result<Vec<super::HttpMirroringServiceMirrorsItem>, String>,
        service: Result<Option<String>, String>,
    }
    impl Default for HttpMirroringService {
        fn default() -> Self {
            Self {
                health_check: Ok(Default::default()),
                max_body_size: Ok(super::defaults::default_i64::<i64, -1>()),
                mirrors: Ok(Default::default()),
                service: Ok(Default::default()),
            }
        }
    }
    impl HttpMirroringService {
        pub fn health_check<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<serde_json::Map<String, serde_json::Value>>,
            T::Error: std::fmt::Display,
        {
            self.health_check = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for health_check: {}", e));
            self
        }
        pub fn max_body_size<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<i64>,
            T::Error: std::fmt::Display,
        {
            self.max_body_size = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for max_body_size: {}", e));
            self
        }
        pub fn mirrors<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::HttpMirroringServiceMirrorsItem>>,
            T::Error: std::fmt::Display,
        {
            self.mirrors = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for mirrors: {}", e));
            self
        }
        pub fn service<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.service = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for service: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpMirroringService> for super::HttpMirroringService {
        type Error = String;
        fn try_from(value: HttpMirroringService) -> Result<Self, String> {
            Ok(Self {
                health_check: value.health_check?,
                max_body_size: value.max_body_size?,
                mirrors: value.mirrors?,
                service: value.service?,
            })
        }
    }
    impl From<super::HttpMirroringService> for HttpMirroringService {
        fn from(value: super::HttpMirroringService) -> Self {
            Self {
                health_check: Ok(value.health_check),
                max_body_size: Ok(value.max_body_size),
                mirrors: Ok(value.mirrors),
                service: Ok(value.service),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpMirroringServiceMirrorsItem {
        name: Result<Option<String>, String>,
        percent: Result<Option<f64>, String>,
    }
    impl Default for HttpMirroringServiceMirrorsItem {
        fn default() -> Self {
            Self {
                name: Ok(Default::default()),
                percent: Ok(Default::default()),
            }
        }
    }
    impl HttpMirroringServiceMirrorsItem {
        pub fn name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for name: {}", e));
            self
        }
        pub fn percent<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<f64>>,
            T::Error: std::fmt::Display,
        {
            self.percent = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for percent: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpMirroringServiceMirrorsItem>
        for super::HttpMirroringServiceMirrorsItem
    {
        type Error = String;
        fn try_from(value: HttpMirroringServiceMirrorsItem) -> Result<Self, String> {
            Ok(Self {
                name: value.name?,
                percent: value.percent?,
            })
        }
    }
    impl From<super::HttpMirroringServiceMirrorsItem> for HttpMirroringServiceMirrorsItem {
        fn from(value: super::HttpMirroringServiceMirrorsItem) -> Self {
            Self {
                name: Ok(value.name),
                percent: Ok(value.percent),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpRouter {
        entry_points: Result<Vec<String>, String>,
        middlewares: Result<Vec<String>, String>,
        priority: Result<u64, String>,
        rule: Result<String, String>,
        service: Result<String, String>,
        tls: Result<Option<super::HttpRouterTls>, String>,
    }
    impl Default for HttpRouter {
        fn default() -> Self {
            Self {
                entry_points: Ok(Default::default()),
                middlewares: Ok(Default::default()),
                priority: Ok(Default::default()),
                rule: Err("no value supplied for rule".to_string()),
                service: Err("no value supplied for service".to_string()),
                tls: Ok(Default::default()),
            }
        }
    }
    impl HttpRouter {
        pub fn entry_points<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.entry_points = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for entry_points: {}", e));
            self
        }
        pub fn middlewares<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.middlewares = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for middlewares: {}", e));
            self
        }
        pub fn priority<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<u64>,
            T::Error: std::fmt::Display,
        {
            self.priority = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for priority: {}", e));
            self
        }
        pub fn rule<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.rule = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for rule: {}", e));
            self
        }
        pub fn service<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.service = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for service: {}", e));
            self
        }
        pub fn tls<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpRouterTls>>,
            T::Error: std::fmt::Display,
        {
            self.tls = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for tls: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpRouter> for super::HttpRouter {
        type Error = String;
        fn try_from(value: HttpRouter) -> Result<Self, String> {
            Ok(Self {
                entry_points: value.entry_points?,
                middlewares: value.middlewares?,
                priority: value.priority?,
                rule: value.rule?,
                service: value.service?,
                tls: value.tls?,
            })
        }
    }
    impl From<super::HttpRouter> for HttpRouter {
        fn from(value: super::HttpRouter) -> Self {
            Self {
                entry_points: Ok(value.entry_points),
                middlewares: Ok(value.middlewares),
                priority: Ok(value.priority),
                rule: Ok(value.rule),
                service: Ok(value.service),
                tls: Ok(value.tls),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpRouterTls {
        cert_resolver: Result<Option<String>, String>,
        domains: Result<Vec<super::HttpRouterTlsDomainsItem>, String>,
        options: Result<Option<String>, String>,
    }
    impl Default for HttpRouterTls {
        fn default() -> Self {
            Self {
                cert_resolver: Ok(Default::default()),
                domains: Ok(Default::default()),
                options: Ok(Default::default()),
            }
        }
    }
    impl HttpRouterTls {
        pub fn cert_resolver<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.cert_resolver = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for cert_resolver: {}", e));
            self
        }
        pub fn domains<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::HttpRouterTlsDomainsItem>>,
            T::Error: std::fmt::Display,
        {
            self.domains = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for domains: {}", e));
            self
        }
        pub fn options<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.options = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for options: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpRouterTls> for super::HttpRouterTls {
        type Error = String;
        fn try_from(value: HttpRouterTls) -> Result<Self, String> {
            Ok(Self {
                cert_resolver: value.cert_resolver?,
                domains: value.domains?,
                options: value.options?,
            })
        }
    }
    impl From<super::HttpRouterTls> for HttpRouterTls {
        fn from(value: super::HttpRouterTls) -> Self {
            Self {
                cert_resolver: Ok(value.cert_resolver),
                domains: Ok(value.domains),
                options: Ok(value.options),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpRouterTlsDomainsItem {
        main: Result<Option<String>, String>,
        sans: Result<Vec<String>, String>,
    }
    impl Default for HttpRouterTlsDomainsItem {
        fn default() -> Self {
            Self {
                main: Ok(Default::default()),
                sans: Ok(Default::default()),
            }
        }
    }
    impl HttpRouterTlsDomainsItem {
        pub fn main<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.main = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for main: {}", e));
            self
        }
        pub fn sans<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.sans = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sans: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpRouterTlsDomainsItem> for super::HttpRouterTlsDomainsItem {
        type Error = String;
        fn try_from(value: HttpRouterTlsDomainsItem) -> Result<Self, String> {
            Ok(Self {
                main: value.main?,
                sans: value.sans?,
            })
        }
    }
    impl From<super::HttpRouterTlsDomainsItem> for HttpRouterTlsDomainsItem {
        fn from(value: super::HttpRouterTlsDomainsItem) -> Self {
            Self {
                main: Ok(value.main),
                sans: Ok(value.sans),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpWeightedService {
        health_check: Result<serde_json::Map<String, serde_json::Value>, String>,
        services: Result<Vec<super::HttpWeightedServiceServicesItem>, String>,
        sticky: Result<Option<super::HttpWeightedServiceSticky>, String>,
    }
    impl Default for HttpWeightedService {
        fn default() -> Self {
            Self {
                health_check: Ok(Default::default()),
                services: Ok(Default::default()),
                sticky: Ok(Default::default()),
            }
        }
    }
    impl HttpWeightedService {
        pub fn health_check<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<serde_json::Map<String, serde_json::Value>>,
            T::Error: std::fmt::Display,
        {
            self.health_check = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for health_check: {}", e));
            self
        }
        pub fn services<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::HttpWeightedServiceServicesItem>>,
            T::Error: std::fmt::Display,
        {
            self.services = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for services: {}", e));
            self
        }
        pub fn sticky<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpWeightedServiceSticky>>,
            T::Error: std::fmt::Display,
        {
            self.sticky = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sticky: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpWeightedService> for super::HttpWeightedService {
        type Error = String;
        fn try_from(value: HttpWeightedService) -> Result<Self, String> {
            Ok(Self {
                health_check: value.health_check?,
                services: value.services?,
                sticky: value.sticky?,
            })
        }
    }
    impl From<super::HttpWeightedService> for HttpWeightedService {
        fn from(value: super::HttpWeightedService) -> Self {
            Self {
                health_check: Ok(value.health_check),
                services: Ok(value.services),
                sticky: Ok(value.sticky),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpWeightedServiceServicesItem {
        name: Result<Option<String>, String>,
        weight: Result<Option<f64>, String>,
    }
    impl Default for HttpWeightedServiceServicesItem {
        fn default() -> Self {
            Self {
                name: Ok(Default::default()),
                weight: Ok(Default::default()),
            }
        }
    }
    impl HttpWeightedServiceServicesItem {
        pub fn name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for name: {}", e));
            self
        }
        pub fn weight<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<f64>>,
            T::Error: std::fmt::Display,
        {
            self.weight = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for weight: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpWeightedServiceServicesItem>
        for super::HttpWeightedServiceServicesItem
    {
        type Error = String;
        fn try_from(value: HttpWeightedServiceServicesItem) -> Result<Self, String> {
            Ok(Self {
                name: value.name?,
                weight: value.weight?,
            })
        }
    }
    impl From<super::HttpWeightedServiceServicesItem> for HttpWeightedServiceServicesItem {
        fn from(value: super::HttpWeightedServiceServicesItem) -> Self {
            Self {
                name: Ok(value.name),
                weight: Ok(value.weight),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpWeightedServiceSticky {
        cookie: Result<Option<super::HttpWeightedServiceStickyCookie>, String>,
    }
    impl Default for HttpWeightedServiceSticky {
        fn default() -> Self {
            Self {
                cookie: Ok(Default::default()),
            }
        }
    }
    impl HttpWeightedServiceSticky {
        pub fn cookie<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::HttpWeightedServiceStickyCookie>>,
            T::Error: std::fmt::Display,
        {
            self.cookie = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for cookie: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpWeightedServiceSticky> for super::HttpWeightedServiceSticky {
        type Error = String;
        fn try_from(value: HttpWeightedServiceSticky) -> Result<Self, String> {
            Ok(Self {
                cookie: value.cookie?,
            })
        }
    }
    impl From<super::HttpWeightedServiceSticky> for HttpWeightedServiceSticky {
        fn from(value: super::HttpWeightedServiceSticky) -> Self {
            Self {
                cookie: Ok(value.cookie),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct HttpWeightedServiceStickyCookie {
        http_only: Result<bool, String>,
        name: Result<Option<String>, String>,
        same_site: Result<String, String>,
        secure: Result<bool, String>,
    }
    impl Default for HttpWeightedServiceStickyCookie {
        fn default() -> Self {
            Self {
                http_only: Ok(Default::default()),
                name: Ok(Default::default()),
                same_site: Ok(Default::default()),
                secure: Ok(Default::default()),
            }
        }
    }
    impl HttpWeightedServiceStickyCookie {
        pub fn http_only<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.http_only = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for http_only: {}", e));
            self
        }
        pub fn name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for name: {}", e));
            self
        }
        pub fn same_site<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.same_site = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for same_site: {}", e));
            self
        }
        pub fn secure<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.secure = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for secure: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<HttpWeightedServiceStickyCookie>
        for super::HttpWeightedServiceStickyCookie
    {
        type Error = String;
        fn try_from(value: HttpWeightedServiceStickyCookie) -> Result<Self, String> {
            Ok(Self {
                http_only: value.http_only?,
                name: value.name?,
                same_site: value.same_site?,
                secure: value.secure?,
            })
        }
    }
    impl From<super::HttpWeightedServiceStickyCookie> for HttpWeightedServiceStickyCookie {
        fn from(value: super::HttpWeightedServiceStickyCookie) -> Self {
            Self {
                http_only: Ok(value.http_only),
                name: Ok(value.name),
                same_site: Ok(value.same_site),
                secure: Ok(value.secure),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct InFlightReqMiddleware {
        amount: Result<Option<i64>, String>,
        source_criterion: Result<Option<super::SourceCriterion>, String>,
    }
    impl Default for InFlightReqMiddleware {
        fn default() -> Self {
            Self {
                amount: Ok(Default::default()),
                source_criterion: Ok(Default::default()),
            }
        }
    }
    impl InFlightReqMiddleware {
        pub fn amount<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.amount = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for amount: {}", e));
            self
        }
        pub fn source_criterion<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::SourceCriterion>>,
            T::Error: std::fmt::Display,
        {
            self.source_criterion = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for source_criterion: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<InFlightReqMiddleware> for super::InFlightReqMiddleware {
        type Error = String;
        fn try_from(value: InFlightReqMiddleware) -> Result<Self, String> {
            Ok(Self {
                amount: value.amount?,
                source_criterion: value.source_criterion?,
            })
        }
    }
    impl From<super::InFlightReqMiddleware> for InFlightReqMiddleware {
        fn from(value: super::InFlightReqMiddleware) -> Self {
            Self {
                amount: Ok(value.amount),
                source_criterion: Ok(value.source_criterion),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct IpStrategy {
        depth: Result<Option<i64>, String>,
        excluded_i_ps: Result<Vec<String>, String>,
    }
    impl Default for IpStrategy {
        fn default() -> Self {
            Self {
                depth: Ok(Default::default()),
                excluded_i_ps: Ok(Default::default()),
            }
        }
    }
    impl IpStrategy {
        pub fn depth<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.depth = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for depth: {}", e));
            self
        }
        pub fn excluded_i_ps<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.excluded_i_ps = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for excluded_i_ps: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<IpStrategy> for super::IpStrategy {
        type Error = String;
        fn try_from(value: IpStrategy) -> Result<Self, String> {
            Ok(Self {
                depth: value.depth?,
                excluded_i_ps: value.excluded_i_ps?,
            })
        }
    }
    impl From<super::IpStrategy> for IpStrategy {
        fn from(value: super::IpStrategy) -> Self {
            Self {
                depth: Ok(value.depth),
                excluded_i_ps: Ok(value.excluded_i_ps),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct IpWhiteListMiddleware {
        ip_strategy: Result<Option<super::IpStrategy>, String>,
        source_range: Result<Vec<String>, String>,
    }
    impl Default for IpWhiteListMiddleware {
        fn default() -> Self {
            Self {
                ip_strategy: Ok(Default::default()),
                source_range: Ok(Default::default()),
            }
        }
    }
    impl IpWhiteListMiddleware {
        pub fn ip_strategy<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::IpStrategy>>,
            T::Error: std::fmt::Display,
        {
            self.ip_strategy = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ip_strategy: {}", e));
            self
        }
        pub fn source_range<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.source_range = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for source_range: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<IpWhiteListMiddleware> for super::IpWhiteListMiddleware {
        type Error = String;
        fn try_from(value: IpWhiteListMiddleware) -> Result<Self, String> {
            Ok(Self {
                ip_strategy: value.ip_strategy?,
                source_range: value.source_range?,
            })
        }
    }
    impl From<super::IpWhiteListMiddleware> for IpWhiteListMiddleware {
        fn from(value: super::IpWhiteListMiddleware) -> Self {
            Self {
                ip_strategy: Ok(value.ip_strategy),
                source_range: Ok(value.source_range),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct PassTlsClientCertMiddleware {
        info: Result<Option<super::PassTlsClientCertMiddlewareInfo>, String>,
        pem: Result<Option<bool>, String>,
    }
    impl Default for PassTlsClientCertMiddleware {
        fn default() -> Self {
            Self {
                info: Ok(Default::default()),
                pem: Ok(Default::default()),
            }
        }
    }
    impl PassTlsClientCertMiddleware {
        pub fn info<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::PassTlsClientCertMiddlewareInfo>>,
            T::Error: std::fmt::Display,
        {
            self.info = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for info: {}", e));
            self
        }
        pub fn pem<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.pem = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for pem: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<PassTlsClientCertMiddleware> for super::PassTlsClientCertMiddleware {
        type Error = String;
        fn try_from(value: PassTlsClientCertMiddleware) -> Result<Self, String> {
            Ok(Self {
                info: value.info?,
                pem: value.pem?,
            })
        }
    }
    impl From<super::PassTlsClientCertMiddleware> for PassTlsClientCertMiddleware {
        fn from(value: super::PassTlsClientCertMiddleware) -> Self {
            Self {
                info: Ok(value.info),
                pem: Ok(value.pem),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct PassTlsClientCertMiddlewareInfo {
        issuer: Result<Option<super::PassTlsClientCertMiddlewareInfoIssuer>, String>,
        not_after: Result<Option<bool>, String>,
        not_before: Result<Option<bool>, String>,
        sans: Result<Option<bool>, String>,
        subject: Result<Option<super::PassTlsClientCertMiddlewareInfoSubject>, String>,
    }
    impl Default for PassTlsClientCertMiddlewareInfo {
        fn default() -> Self {
            Self {
                issuer: Ok(Default::default()),
                not_after: Ok(Default::default()),
                not_before: Ok(Default::default()),
                sans: Ok(Default::default()),
                subject: Ok(Default::default()),
            }
        }
    }
    impl PassTlsClientCertMiddlewareInfo {
        pub fn issuer<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::PassTlsClientCertMiddlewareInfoIssuer>>,
            T::Error: std::fmt::Display,
        {
            self.issuer = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for issuer: {}", e));
            self
        }
        pub fn not_after<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.not_after = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for not_after: {}", e));
            self
        }
        pub fn not_before<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.not_before = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for not_before: {}", e));
            self
        }
        pub fn sans<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.sans = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sans: {}", e));
            self
        }
        pub fn subject<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::PassTlsClientCertMiddlewareInfoSubject>>,
            T::Error: std::fmt::Display,
        {
            self.subject = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for subject: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<PassTlsClientCertMiddlewareInfo>
        for super::PassTlsClientCertMiddlewareInfo
    {
        type Error = String;
        fn try_from(value: PassTlsClientCertMiddlewareInfo) -> Result<Self, String> {
            Ok(Self {
                issuer: value.issuer?,
                not_after: value.not_after?,
                not_before: value.not_before?,
                sans: value.sans?,
                subject: value.subject?,
            })
        }
    }
    impl From<super::PassTlsClientCertMiddlewareInfo> for PassTlsClientCertMiddlewareInfo {
        fn from(value: super::PassTlsClientCertMiddlewareInfo) -> Self {
            Self {
                issuer: Ok(value.issuer),
                not_after: Ok(value.not_after),
                not_before: Ok(value.not_before),
                sans: Ok(value.sans),
                subject: Ok(value.subject),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct PassTlsClientCertMiddlewareInfoIssuer {
        common_name: Result<Option<bool>, String>,
        country: Result<Option<bool>, String>,
        domain_component: Result<Option<bool>, String>,
        locality: Result<Option<bool>, String>,
        organization: Result<Option<bool>, String>,
        province: Result<Option<bool>, String>,
        serial_number: Result<Option<bool>, String>,
    }
    impl Default for PassTlsClientCertMiddlewareInfoIssuer {
        fn default() -> Self {
            Self {
                common_name: Ok(Default::default()),
                country: Ok(Default::default()),
                domain_component: Ok(Default::default()),
                locality: Ok(Default::default()),
                organization: Ok(Default::default()),
                province: Ok(Default::default()),
                serial_number: Ok(Default::default()),
            }
        }
    }
    impl PassTlsClientCertMiddlewareInfoIssuer {
        pub fn common_name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.common_name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for common_name: {}", e));
            self
        }
        pub fn country<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.country = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for country: {}", e));
            self
        }
        pub fn domain_component<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.domain_component = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for domain_component: {}",
                    e
                )
            });
            self
        }
        pub fn locality<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.locality = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for locality: {}", e));
            self
        }
        pub fn organization<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.organization = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for organization: {}", e));
            self
        }
        pub fn province<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.province = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for province: {}", e));
            self
        }
        pub fn serial_number<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.serial_number = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for serial_number: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<PassTlsClientCertMiddlewareInfoIssuer>
        for super::PassTlsClientCertMiddlewareInfoIssuer
    {
        type Error = String;
        fn try_from(value: PassTlsClientCertMiddlewareInfoIssuer) -> Result<Self, String> {
            Ok(Self {
                common_name: value.common_name?,
                country: value.country?,
                domain_component: value.domain_component?,
                locality: value.locality?,
                organization: value.organization?,
                province: value.province?,
                serial_number: value.serial_number?,
            })
        }
    }
    impl From<super::PassTlsClientCertMiddlewareInfoIssuer> for PassTlsClientCertMiddlewareInfoIssuer {
        fn from(value: super::PassTlsClientCertMiddlewareInfoIssuer) -> Self {
            Self {
                common_name: Ok(value.common_name),
                country: Ok(value.country),
                domain_component: Ok(value.domain_component),
                locality: Ok(value.locality),
                organization: Ok(value.organization),
                province: Ok(value.province),
                serial_number: Ok(value.serial_number),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct PassTlsClientCertMiddlewareInfoSubject {
        common_name: Result<Option<bool>, String>,
        country: Result<Option<bool>, String>,
        domain_component: Result<Option<bool>, String>,
        locality: Result<Option<bool>, String>,
        organization: Result<Option<bool>, String>,
        province: Result<Option<bool>, String>,
        serial_number: Result<Option<bool>, String>,
    }
    impl Default for PassTlsClientCertMiddlewareInfoSubject {
        fn default() -> Self {
            Self {
                common_name: Ok(Default::default()),
                country: Ok(Default::default()),
                domain_component: Ok(Default::default()),
                locality: Ok(Default::default()),
                organization: Ok(Default::default()),
                province: Ok(Default::default()),
                serial_number: Ok(Default::default()),
            }
        }
    }
    impl PassTlsClientCertMiddlewareInfoSubject {
        pub fn common_name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.common_name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for common_name: {}", e));
            self
        }
        pub fn country<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.country = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for country: {}", e));
            self
        }
        pub fn domain_component<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.domain_component = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for domain_component: {}",
                    e
                )
            });
            self
        }
        pub fn locality<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.locality = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for locality: {}", e));
            self
        }
        pub fn organization<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.organization = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for organization: {}", e));
            self
        }
        pub fn province<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.province = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for province: {}", e));
            self
        }
        pub fn serial_number<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.serial_number = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for serial_number: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<PassTlsClientCertMiddlewareInfoSubject>
        for super::PassTlsClientCertMiddlewareInfoSubject
    {
        type Error = String;
        fn try_from(value: PassTlsClientCertMiddlewareInfoSubject) -> Result<Self, String> {
            Ok(Self {
                common_name: value.common_name?,
                country: value.country?,
                domain_component: value.domain_component?,
                locality: value.locality?,
                organization: value.organization?,
                province: value.province?,
                serial_number: value.serial_number?,
            })
        }
    }
    impl From<super::PassTlsClientCertMiddlewareInfoSubject>
        for PassTlsClientCertMiddlewareInfoSubject
    {
        fn from(value: super::PassTlsClientCertMiddlewareInfoSubject) -> Self {
            Self {
                common_name: Ok(value.common_name),
                country: Ok(value.country),
                domain_component: Ok(value.domain_component),
                locality: Ok(value.locality),
                organization: Ok(value.organization),
                province: Ok(value.province),
                serial_number: Ok(value.serial_number),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RateLimitMiddleware {
        average: Result<Option<super::RateLimitMiddlewareAverage>, String>,
        burst: Result<Option<f64>, String>,
        period: Result<Option<super::RateLimitMiddlewarePeriod>, String>,
        source_criterion: Result<Option<super::SourceCriterion>, String>,
    }
    impl Default for RateLimitMiddleware {
        fn default() -> Self {
            Self {
                average: Ok(Default::default()),
                burst: Ok(Default::default()),
                period: Ok(Default::default()),
                source_criterion: Ok(Default::default()),
            }
        }
    }
    impl RateLimitMiddleware {
        pub fn average<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RateLimitMiddlewareAverage>>,
            T::Error: std::fmt::Display,
        {
            self.average = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for average: {}", e));
            self
        }
        pub fn burst<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<f64>>,
            T::Error: std::fmt::Display,
        {
            self.burst = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for burst: {}", e));
            self
        }
        pub fn period<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RateLimitMiddlewarePeriod>>,
            T::Error: std::fmt::Display,
        {
            self.period = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for period: {}", e));
            self
        }
        pub fn source_criterion<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::SourceCriterion>>,
            T::Error: std::fmt::Display,
        {
            self.source_criterion = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for source_criterion: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<RateLimitMiddleware> for super::RateLimitMiddleware {
        type Error = String;
        fn try_from(value: RateLimitMiddleware) -> Result<Self, String> {
            Ok(Self {
                average: value.average?,
                burst: value.burst?,
                period: value.period?,
                source_criterion: value.source_criterion?,
            })
        }
    }
    impl From<super::RateLimitMiddleware> for RateLimitMiddleware {
        fn from(value: super::RateLimitMiddleware) -> Self {
            Self {
                average: Ok(value.average),
                burst: Ok(value.burst),
                period: Ok(value.period),
                source_criterion: Ok(value.source_criterion),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RedirectRegexMiddleware {
        permanent: Result<Option<bool>, String>,
        regex: Result<Option<String>, String>,
        replacement: Result<Option<String>, String>,
    }
    impl Default for RedirectRegexMiddleware {
        fn default() -> Self {
            Self {
                permanent: Ok(Default::default()),
                regex: Ok(Default::default()),
                replacement: Ok(Default::default()),
            }
        }
    }
    impl RedirectRegexMiddleware {
        pub fn permanent<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.permanent = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for permanent: {}", e));
            self
        }
        pub fn regex<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.regex = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for regex: {}", e));
            self
        }
        pub fn replacement<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.replacement = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for replacement: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RedirectRegexMiddleware> for super::RedirectRegexMiddleware {
        type Error = String;
        fn try_from(value: RedirectRegexMiddleware) -> Result<Self, String> {
            Ok(Self {
                permanent: value.permanent?,
                regex: value.regex?,
                replacement: value.replacement?,
            })
        }
    }
    impl From<super::RedirectRegexMiddleware> for RedirectRegexMiddleware {
        fn from(value: super::RedirectRegexMiddleware) -> Self {
            Self {
                permanent: Ok(value.permanent),
                regex: Ok(value.regex),
                replacement: Ok(value.replacement),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RedirectSchemeMiddleware {
        permanent: Result<Option<bool>, String>,
        port: Result<Option<String>, String>,
        scheme: Result<Option<String>, String>,
    }
    impl Default for RedirectSchemeMiddleware {
        fn default() -> Self {
            Self {
                permanent: Ok(Default::default()),
                port: Ok(Default::default()),
                scheme: Ok(Default::default()),
            }
        }
    }
    impl RedirectSchemeMiddleware {
        pub fn permanent<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.permanent = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for permanent: {}", e));
            self
        }
        pub fn port<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.port = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for port: {}", e));
            self
        }
        pub fn scheme<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.scheme = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for scheme: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RedirectSchemeMiddleware> for super::RedirectSchemeMiddleware {
        type Error = String;
        fn try_from(value: RedirectSchemeMiddleware) -> Result<Self, String> {
            Ok(Self {
                permanent: value.permanent?,
                port: value.port?,
                scheme: value.scheme?,
            })
        }
    }
    impl From<super::RedirectSchemeMiddleware> for RedirectSchemeMiddleware {
        fn from(value: super::RedirectSchemeMiddleware) -> Self {
            Self {
                permanent: Ok(value.permanent),
                port: Ok(value.port),
                scheme: Ok(value.scheme),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ReplacePathMiddleware {
        path: Result<Option<String>, String>,
    }
    impl Default for ReplacePathMiddleware {
        fn default() -> Self {
            Self {
                path: Ok(Default::default()),
            }
        }
    }
    impl ReplacePathMiddleware {
        pub fn path<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.path = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for path: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<ReplacePathMiddleware> for super::ReplacePathMiddleware {
        type Error = String;
        fn try_from(value: ReplacePathMiddleware) -> Result<Self, String> {
            Ok(Self { path: value.path? })
        }
    }
    impl From<super::ReplacePathMiddleware> for ReplacePathMiddleware {
        fn from(value: super::ReplacePathMiddleware) -> Self {
            Self {
                path: Ok(value.path),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ReplacePathRegexMiddleware {
        regex: Result<Option<String>, String>,
        replacement: Result<Option<String>, String>,
    }
    impl Default for ReplacePathRegexMiddleware {
        fn default() -> Self {
            Self {
                regex: Ok(Default::default()),
                replacement: Ok(Default::default()),
            }
        }
    }
    impl ReplacePathRegexMiddleware {
        pub fn regex<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.regex = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for regex: {}", e));
            self
        }
        pub fn replacement<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.replacement = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for replacement: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<ReplacePathRegexMiddleware> for super::ReplacePathRegexMiddleware {
        type Error = String;
        fn try_from(value: ReplacePathRegexMiddleware) -> Result<Self, String> {
            Ok(Self {
                regex: value.regex?,
                replacement: value.replacement?,
            })
        }
    }
    impl From<super::ReplacePathRegexMiddleware> for ReplacePathRegexMiddleware {
        fn from(value: super::ReplacePathRegexMiddleware) -> Self {
            Self {
                regex: Ok(value.regex),
                replacement: Ok(value.replacement),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RetryMiddleware {
        attempts: Result<i64, String>,
        initial_interval: Result<Option<String>, String>,
    }
    impl Default for RetryMiddleware {
        fn default() -> Self {
            Self {
                attempts: Err("no value supplied for attempts".to_string()),
                initial_interval: Ok(Default::default()),
            }
        }
    }
    impl RetryMiddleware {
        pub fn attempts<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<i64>,
            T::Error: std::fmt::Display,
        {
            self.attempts = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for attempts: {}", e));
            self
        }
        pub fn initial_interval<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.initial_interval = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for initial_interval: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<RetryMiddleware> for super::RetryMiddleware {
        type Error = String;
        fn try_from(value: RetryMiddleware) -> Result<Self, String> {
            Ok(Self {
                attempts: value.attempts?,
                initial_interval: value.initial_interval?,
            })
        }
    }
    impl From<super::RetryMiddleware> for RetryMiddleware {
        fn from(value: super::RetryMiddleware) -> Self {
            Self {
                attempts: Ok(value.attempts),
                initial_interval: Ok(value.initial_interval),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct Root {
        http: Result<Option<super::RootHttp>, String>,
        tcp: Result<Option<super::RootTcp>, String>,
        tls: Result<Option<super::RootTls>, String>,
        udp: Result<Option<super::RootUdp>, String>,
    }
    impl Default for Root {
        fn default() -> Self {
            Self {
                http: Ok(Default::default()),
                tcp: Ok(Default::default()),
                tls: Ok(Default::default()),
                udp: Ok(Default::default()),
            }
        }
    }
    impl Root {
        pub fn http<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RootHttp>>,
            T::Error: std::fmt::Display,
        {
            self.http = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for http: {}", e));
            self
        }
        pub fn tcp<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RootTcp>>,
            T::Error: std::fmt::Display,
        {
            self.tcp = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for tcp: {}", e));
            self
        }
        pub fn tls<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RootTls>>,
            T::Error: std::fmt::Display,
        {
            self.tls = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for tls: {}", e));
            self
        }
        pub fn udp<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RootUdp>>,
            T::Error: std::fmt::Display,
        {
            self.udp = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for udp: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<Root> for super::Root {
        type Error = String;
        fn try_from(value: Root) -> Result<Self, String> {
            Ok(Self {
                http: value.http?,
                tcp: value.tcp?,
                tls: value.tls?,
                udp: value.udp?,
            })
        }
    }
    impl From<super::Root> for Root {
        fn from(value: super::Root) -> Self {
            Self {
                http: Ok(value.http),
                tcp: Ok(value.tcp),
                tls: Ok(value.tls),
                udp: Ok(value.udp),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootHttp {
        middlewares: Result<std::collections::HashMap<String, super::HttpMiddleware>, String>,
        routers: Result<std::collections::HashMap<String, super::HttpRouter>, String>,
        services: Result<std::collections::HashMap<String, super::HttpService>, String>,
    }
    impl Default for RootHttp {
        fn default() -> Self {
            Self {
                middlewares: Ok(Default::default()),
                routers: Ok(Default::default()),
                services: Ok(Default::default()),
            }
        }
    }
    impl RootHttp {
        pub fn middlewares<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::HttpMiddleware>>,
            T::Error: std::fmt::Display,
        {
            self.middlewares = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for middlewares: {}", e));
            self
        }
        pub fn routers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::HttpRouter>>,
            T::Error: std::fmt::Display,
        {
            self.routers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for routers: {}", e));
            self
        }
        pub fn services<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::HttpService>>,
            T::Error: std::fmt::Display,
        {
            self.services = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for services: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RootHttp> for super::RootHttp {
        type Error = String;
        fn try_from(value: RootHttp) -> Result<Self, String> {
            Ok(Self {
                middlewares: value.middlewares?,
                routers: value.routers?,
                services: value.services?,
            })
        }
    }
    impl From<super::RootHttp> for RootHttp {
        fn from(value: super::RootHttp) -> Self {
            Self {
                middlewares: Ok(value.middlewares),
                routers: Ok(value.routers),
                services: Ok(value.services),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootTcp {
        routers: Result<std::collections::HashMap<String, super::TcpRouter>, String>,
        services: Result<std::collections::HashMap<String, super::TcpService>, String>,
    }
    impl Default for RootTcp {
        fn default() -> Self {
            Self {
                routers: Ok(Default::default()),
                services: Ok(Default::default()),
            }
        }
    }
    impl RootTcp {
        pub fn routers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::TcpRouter>>,
            T::Error: std::fmt::Display,
        {
            self.routers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for routers: {}", e));
            self
        }
        pub fn services<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::TcpService>>,
            T::Error: std::fmt::Display,
        {
            self.services = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for services: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RootTcp> for super::RootTcp {
        type Error = String;
        fn try_from(value: RootTcp) -> Result<Self, String> {
            Ok(Self {
                routers: value.routers?,
                services: value.services?,
            })
        }
    }
    impl From<super::RootTcp> for RootTcp {
        fn from(value: super::RootTcp) -> Self {
            Self {
                routers: Ok(value.routers),
                services: Ok(value.services),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootTls {
        certificates: Result<Vec<super::RootTlsCertificatesItem>, String>,
        options: Result<Option<super::RootTlsOptions>, String>,
        stores: Result<Option<super::RootTlsStores>, String>,
    }
    impl Default for RootTls {
        fn default() -> Self {
            Self {
                certificates: Ok(Default::default()),
                options: Ok(Default::default()),
                stores: Ok(Default::default()),
            }
        }
    }
    impl RootTls {
        pub fn certificates<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::RootTlsCertificatesItem>>,
            T::Error: std::fmt::Display,
        {
            self.certificates = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for certificates: {}", e));
            self
        }
        pub fn options<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RootTlsOptions>>,
            T::Error: std::fmt::Display,
        {
            self.options = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for options: {}", e));
            self
        }
        pub fn stores<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::RootTlsStores>>,
            T::Error: std::fmt::Display,
        {
            self.stores = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for stores: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RootTls> for super::RootTls {
        type Error = String;
        fn try_from(value: RootTls) -> Result<Self, String> {
            Ok(Self {
                certificates: value.certificates?,
                options: value.options?,
                stores: value.stores?,
            })
        }
    }
    impl From<super::RootTls> for RootTls {
        fn from(value: super::RootTls) -> Self {
            Self {
                certificates: Ok(value.certificates),
                options: Ok(value.options),
                stores: Ok(value.stores),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootTlsCertificatesItem {
        cert_file: Result<Option<String>, String>,
        key_file: Result<Option<String>, String>,
        stores: Result<Vec<String>, String>,
    }
    impl Default for RootTlsCertificatesItem {
        fn default() -> Self {
            Self {
                cert_file: Ok(Default::default()),
                key_file: Ok(Default::default()),
                stores: Ok(Default::default()),
            }
        }
    }
    impl RootTlsCertificatesItem {
        pub fn cert_file<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.cert_file = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for cert_file: {}", e));
            self
        }
        pub fn key_file<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.key_file = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for key_file: {}", e));
            self
        }
        pub fn stores<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.stores = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for stores: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RootTlsCertificatesItem> for super::RootTlsCertificatesItem {
        type Error = String;
        fn try_from(value: RootTlsCertificatesItem) -> Result<Self, String> {
            Ok(Self {
                cert_file: value.cert_file?,
                key_file: value.key_file?,
                stores: value.stores?,
            })
        }
    }
    impl From<super::RootTlsCertificatesItem> for RootTlsCertificatesItem {
        fn from(value: super::RootTlsCertificatesItem) -> Self {
            Self {
                cert_file: Ok(value.cert_file),
                key_file: Ok(value.key_file),
                stores: Ok(value.stores),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootTlsOptions {}
    impl Default for RootTlsOptions {
        fn default() -> Self {
            Self {}
        }
    }
    impl RootTlsOptions {}
    impl std::convert::TryFrom<RootTlsOptions> for super::RootTlsOptions {
        type Error = String;
        fn try_from(value: RootTlsOptions) -> Result<Self, String> {
            Ok(Self {})
        }
    }
    impl From<super::RootTlsOptions> for RootTlsOptions {
        fn from(value: super::RootTlsOptions) -> Self {
            Self {}
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootTlsStores {}
    impl Default for RootTlsStores {
        fn default() -> Self {
            Self {}
        }
    }
    impl RootTlsStores {}
    impl std::convert::TryFrom<RootTlsStores> for super::RootTlsStores {
        type Error = String;
        fn try_from(value: RootTlsStores) -> Result<Self, String> {
            Ok(Self {})
        }
    }
    impl From<super::RootTlsStores> for RootTlsStores {
        fn from(value: super::RootTlsStores) -> Self {
            Self {}
        }
    }
    #[derive(Clone, Debug)]
    pub struct RootUdp {
        routers: Result<std::collections::HashMap<String, super::UdpRouter>, String>,
        services: Result<std::collections::HashMap<String, super::UdpService>, String>,
    }
    impl Default for RootUdp {
        fn default() -> Self {
            Self {
                routers: Ok(Default::default()),
                services: Ok(Default::default()),
            }
        }
    }
    impl RootUdp {
        pub fn routers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::UdpRouter>>,
            T::Error: std::fmt::Display,
        {
            self.routers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for routers: {}", e));
            self
        }
        pub fn services<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<std::collections::HashMap<String, super::UdpService>>,
            T::Error: std::fmt::Display,
        {
            self.services = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for services: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<RootUdp> for super::RootUdp {
        type Error = String;
        fn try_from(value: RootUdp) -> Result<Self, String> {
            Ok(Self {
                routers: value.routers?,
                services: value.services?,
            })
        }
    }
    impl From<super::RootUdp> for RootUdp {
        fn from(value: super::RootUdp) -> Self {
            Self {
                routers: Ok(value.routers),
                services: Ok(value.services),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct SourceCriterion {
        ip_strategy: Result<Option<super::IpStrategy>, String>,
        request_header_name: Result<Option<String>, String>,
        request_host: Result<Option<bool>, String>,
    }
    impl Default for SourceCriterion {
        fn default() -> Self {
            Self {
                ip_strategy: Ok(Default::default()),
                request_header_name: Ok(Default::default()),
                request_host: Ok(Default::default()),
            }
        }
    }
    impl SourceCriterion {
        pub fn ip_strategy<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::IpStrategy>>,
            T::Error: std::fmt::Display,
        {
            self.ip_strategy = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for ip_strategy: {}", e));
            self
        }
        pub fn request_header_name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.request_header_name = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for request_header_name: {}",
                    e
                )
            });
            self
        }
        pub fn request_host<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.request_host = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for request_host: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<SourceCriterion> for super::SourceCriterion {
        type Error = String;
        fn try_from(value: SourceCriterion) -> Result<Self, String> {
            Ok(Self {
                ip_strategy: value.ip_strategy?,
                request_header_name: value.request_header_name?,
                request_host: value.request_host?,
            })
        }
    }
    impl From<super::SourceCriterion> for SourceCriterion {
        fn from(value: super::SourceCriterion) -> Self {
            Self {
                ip_strategy: Ok(value.ip_strategy),
                request_header_name: Ok(value.request_header_name),
                request_host: Ok(value.request_host),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct StripPrefixMiddleware {
        force_slash: Result<Option<bool>, String>,
        prefixes: Result<Vec<String>, String>,
    }
    impl Default for StripPrefixMiddleware {
        fn default() -> Self {
            Self {
                force_slash: Ok(Default::default()),
                prefixes: Ok(Default::default()),
            }
        }
    }
    impl StripPrefixMiddleware {
        pub fn force_slash<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<bool>>,
            T::Error: std::fmt::Display,
        {
            self.force_slash = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for force_slash: {}", e));
            self
        }
        pub fn prefixes<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.prefixes = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for prefixes: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<StripPrefixMiddleware> for super::StripPrefixMiddleware {
        type Error = String;
        fn try_from(value: StripPrefixMiddleware) -> Result<Self, String> {
            Ok(Self {
                force_slash: value.force_slash?,
                prefixes: value.prefixes?,
            })
        }
    }
    impl From<super::StripPrefixMiddleware> for StripPrefixMiddleware {
        fn from(value: super::StripPrefixMiddleware) -> Self {
            Self {
                force_slash: Ok(value.force_slash),
                prefixes: Ok(value.prefixes),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct StripPrefixRegexMiddleware {
        regex: Result<Vec<String>, String>,
    }
    impl Default for StripPrefixRegexMiddleware {
        fn default() -> Self {
            Self {
                regex: Ok(Default::default()),
            }
        }
    }
    impl StripPrefixRegexMiddleware {
        pub fn regex<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.regex = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for regex: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<StripPrefixRegexMiddleware> for super::StripPrefixRegexMiddleware {
        type Error = String;
        fn try_from(value: StripPrefixRegexMiddleware) -> Result<Self, String> {
            Ok(Self {
                regex: value.regex?,
            })
        }
    }
    impl From<super::StripPrefixRegexMiddleware> for StripPrefixRegexMiddleware {
        fn from(value: super::StripPrefixRegexMiddleware) -> Self {
            Self {
                regex: Ok(value.regex),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpLoadBalancerService {
        proxy_protocol: Result<Option<super::TcpLoadBalancerServiceProxyProtocol>, String>,
        servers: Result<Vec<super::TcpLoadBalancerServiceServersItem>, String>,
        termination_delay: Result<Option<f64>, String>,
    }
    impl Default for TcpLoadBalancerService {
        fn default() -> Self {
            Self {
                proxy_protocol: Ok(Default::default()),
                servers: Err("no value supplied for servers".to_string()),
                termination_delay: Ok(Default::default()),
            }
        }
    }
    impl TcpLoadBalancerService {
        pub fn proxy_protocol<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::TcpLoadBalancerServiceProxyProtocol>>,
            T::Error: std::fmt::Display,
        {
            self.proxy_protocol = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for proxy_protocol: {}", e));
            self
        }
        pub fn servers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::TcpLoadBalancerServiceServersItem>>,
            T::Error: std::fmt::Display,
        {
            self.servers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for servers: {}", e));
            self
        }
        pub fn termination_delay<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<f64>>,
            T::Error: std::fmt::Display,
        {
            self.termination_delay = value.try_into().map_err(|e| {
                format!(
                    "error converting supplied value for termination_delay: {}",
                    e
                )
            });
            self
        }
    }
    impl std::convert::TryFrom<TcpLoadBalancerService> for super::TcpLoadBalancerService {
        type Error = String;
        fn try_from(value: TcpLoadBalancerService) -> Result<Self, String> {
            Ok(Self {
                proxy_protocol: value.proxy_protocol?,
                servers: value.servers?,
                termination_delay: value.termination_delay?,
            })
        }
    }
    impl From<super::TcpLoadBalancerService> for TcpLoadBalancerService {
        fn from(value: super::TcpLoadBalancerService) -> Self {
            Self {
                proxy_protocol: Ok(value.proxy_protocol),
                servers: Ok(value.servers),
                termination_delay: Ok(value.termination_delay),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpLoadBalancerServiceProxyProtocol {
        version: Result<Option<i64>, String>,
    }
    impl Default for TcpLoadBalancerServiceProxyProtocol {
        fn default() -> Self {
            Self {
                version: Ok(Default::default()),
            }
        }
    }
    impl TcpLoadBalancerServiceProxyProtocol {
        pub fn version<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<i64>>,
            T::Error: std::fmt::Display,
        {
            self.version = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for version: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpLoadBalancerServiceProxyProtocol>
        for super::TcpLoadBalancerServiceProxyProtocol
    {
        type Error = String;
        fn try_from(value: TcpLoadBalancerServiceProxyProtocol) -> Result<Self, String> {
            Ok(Self {
                version: value.version?,
            })
        }
    }
    impl From<super::TcpLoadBalancerServiceProxyProtocol> for TcpLoadBalancerServiceProxyProtocol {
        fn from(value: super::TcpLoadBalancerServiceProxyProtocol) -> Self {
            Self {
                version: Ok(value.version),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpLoadBalancerServiceServersItem {
        address: Result<String, String>,
    }
    impl Default for TcpLoadBalancerServiceServersItem {
        fn default() -> Self {
            Self {
                address: Err("no value supplied for address".to_string()),
            }
        }
    }
    impl TcpLoadBalancerServiceServersItem {
        pub fn address<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.address = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for address: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpLoadBalancerServiceServersItem>
        for super::TcpLoadBalancerServiceServersItem
    {
        type Error = String;
        fn try_from(value: TcpLoadBalancerServiceServersItem) -> Result<Self, String> {
            Ok(Self {
                address: value.address?,
            })
        }
    }
    impl From<super::TcpLoadBalancerServiceServersItem> for TcpLoadBalancerServiceServersItem {
        fn from(value: super::TcpLoadBalancerServiceServersItem) -> Self {
            Self {
                address: Ok(value.address),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpRouter {
        entry_points: Result<Vec<String>, String>,
        middlewares: Result<Vec<String>, String>,
        priority: Result<u64, String>,
        rule: Result<String, String>,
        service: Result<String, String>,
        tls: Result<Option<super::TcpRouterTls>, String>,
    }
    impl Default for TcpRouter {
        fn default() -> Self {
            Self {
                entry_points: Ok(Default::default()),
                middlewares: Ok(Default::default()),
                priority: Ok(Default::default()),
                rule: Err("no value supplied for rule".to_string()),
                service: Err("no value supplied for service".to_string()),
                tls: Ok(Default::default()),
            }
        }
    }
    impl TcpRouter {
        pub fn entry_points<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.entry_points = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for entry_points: {}", e));
            self
        }
        pub fn middlewares<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.middlewares = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for middlewares: {}", e));
            self
        }
        pub fn priority<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<u64>,
            T::Error: std::fmt::Display,
        {
            self.priority = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for priority: {}", e));
            self
        }
        pub fn rule<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.rule = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for rule: {}", e));
            self
        }
        pub fn service<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.service = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for service: {}", e));
            self
        }
        pub fn tls<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<super::TcpRouterTls>>,
            T::Error: std::fmt::Display,
        {
            self.tls = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for tls: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpRouter> for super::TcpRouter {
        type Error = String;
        fn try_from(value: TcpRouter) -> Result<Self, String> {
            Ok(Self {
                entry_points: value.entry_points?,
                middlewares: value.middlewares?,
                priority: value.priority?,
                rule: value.rule?,
                service: value.service?,
                tls: value.tls?,
            })
        }
    }
    impl From<super::TcpRouter> for TcpRouter {
        fn from(value: super::TcpRouter) -> Self {
            Self {
                entry_points: Ok(value.entry_points),
                middlewares: Ok(value.middlewares),
                priority: Ok(value.priority),
                rule: Ok(value.rule),
                service: Ok(value.service),
                tls: Ok(value.tls),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpRouterTls {
        cert_resolver: Result<Option<String>, String>,
        domains: Result<Vec<super::TcpRouterTlsDomainsItem>, String>,
        options: Result<Option<String>, String>,
        passthrough: Result<bool, String>,
    }
    impl Default for TcpRouterTls {
        fn default() -> Self {
            Self {
                cert_resolver: Ok(Default::default()),
                domains: Ok(Default::default()),
                options: Ok(Default::default()),
                passthrough: Ok(Default::default()),
            }
        }
    }
    impl TcpRouterTls {
        pub fn cert_resolver<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.cert_resolver = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for cert_resolver: {}", e));
            self
        }
        pub fn domains<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::TcpRouterTlsDomainsItem>>,
            T::Error: std::fmt::Display,
        {
            self.domains = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for domains: {}", e));
            self
        }
        pub fn options<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.options = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for options: {}", e));
            self
        }
        pub fn passthrough<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<bool>,
            T::Error: std::fmt::Display,
        {
            self.passthrough = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for passthrough: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpRouterTls> for super::TcpRouterTls {
        type Error = String;
        fn try_from(value: TcpRouterTls) -> Result<Self, String> {
            Ok(Self {
                cert_resolver: value.cert_resolver?,
                domains: value.domains?,
                options: value.options?,
                passthrough: value.passthrough?,
            })
        }
    }
    impl From<super::TcpRouterTls> for TcpRouterTls {
        fn from(value: super::TcpRouterTls) -> Self {
            Self {
                cert_resolver: Ok(value.cert_resolver),
                domains: Ok(value.domains),
                options: Ok(value.options),
                passthrough: Ok(value.passthrough),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpRouterTlsDomainsItem {
        main: Result<Option<String>, String>,
        sans: Result<Vec<String>, String>,
    }
    impl Default for TcpRouterTlsDomainsItem {
        fn default() -> Self {
            Self {
                main: Ok(Default::default()),
                sans: Ok(Default::default()),
            }
        }
    }
    impl TcpRouterTlsDomainsItem {
        pub fn main<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Option<String>>,
            T::Error: std::fmt::Display,
        {
            self.main = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for main: {}", e));
            self
        }
        pub fn sans<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.sans = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for sans: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpRouterTlsDomainsItem> for super::TcpRouterTlsDomainsItem {
        type Error = String;
        fn try_from(value: TcpRouterTlsDomainsItem) -> Result<Self, String> {
            Ok(Self {
                main: value.main?,
                sans: value.sans?,
            })
        }
    }
    impl From<super::TcpRouterTlsDomainsItem> for TcpRouterTlsDomainsItem {
        fn from(value: super::TcpRouterTlsDomainsItem) -> Self {
            Self {
                main: Ok(value.main),
                sans: Ok(value.sans),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpWeightedService {
        services: Result<Vec<super::TcpWeightedServiceServicesItem>, String>,
    }
    impl Default for TcpWeightedService {
        fn default() -> Self {
            Self {
                services: Err("no value supplied for services".to_string()),
            }
        }
    }
    impl TcpWeightedService {
        pub fn services<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::TcpWeightedServiceServicesItem>>,
            T::Error: std::fmt::Display,
        {
            self.services = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for services: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpWeightedService> for super::TcpWeightedService {
        type Error = String;
        fn try_from(value: TcpWeightedService) -> Result<Self, String> {
            Ok(Self {
                services: value.services?,
            })
        }
    }
    impl From<super::TcpWeightedService> for TcpWeightedService {
        fn from(value: super::TcpWeightedService) -> Self {
            Self {
                services: Ok(value.services),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct TcpWeightedServiceServicesItem {
        name: Result<String, String>,
        weight: Result<f64, String>,
    }
    impl Default for TcpWeightedServiceServicesItem {
        fn default() -> Self {
            Self {
                name: Err("no value supplied for name".to_string()),
                weight: Err("no value supplied for weight".to_string()),
            }
        }
    }
    impl TcpWeightedServiceServicesItem {
        pub fn name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for name: {}", e));
            self
        }
        pub fn weight<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<f64>,
            T::Error: std::fmt::Display,
        {
            self.weight = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for weight: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<TcpWeightedServiceServicesItem>
        for super::TcpWeightedServiceServicesItem
    {
        type Error = String;
        fn try_from(value: TcpWeightedServiceServicesItem) -> Result<Self, String> {
            Ok(Self {
                name: value.name?,
                weight: value.weight?,
            })
        }
    }
    impl From<super::TcpWeightedServiceServicesItem> for TcpWeightedServiceServicesItem {
        fn from(value: super::TcpWeightedServiceServicesItem) -> Self {
            Self {
                name: Ok(value.name),
                weight: Ok(value.weight),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct UdpLoadBalancerService {
        servers: Result<Vec<super::UdpLoadBalancerServiceServersItem>, String>,
    }
    impl Default for UdpLoadBalancerService {
        fn default() -> Self {
            Self {
                servers: Err("no value supplied for servers".to_string()),
            }
        }
    }
    impl UdpLoadBalancerService {
        pub fn servers<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::UdpLoadBalancerServiceServersItem>>,
            T::Error: std::fmt::Display,
        {
            self.servers = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for servers: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<UdpLoadBalancerService> for super::UdpLoadBalancerService {
        type Error = String;
        fn try_from(value: UdpLoadBalancerService) -> Result<Self, String> {
            Ok(Self {
                servers: value.servers?,
            })
        }
    }
    impl From<super::UdpLoadBalancerService> for UdpLoadBalancerService {
        fn from(value: super::UdpLoadBalancerService) -> Self {
            Self {
                servers: Ok(value.servers),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct UdpLoadBalancerServiceServersItem {
        address: Result<String, String>,
    }
    impl Default for UdpLoadBalancerServiceServersItem {
        fn default() -> Self {
            Self {
                address: Err("no value supplied for address".to_string()),
            }
        }
    }
    impl UdpLoadBalancerServiceServersItem {
        pub fn address<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.address = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for address: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<UdpLoadBalancerServiceServersItem>
        for super::UdpLoadBalancerServiceServersItem
    {
        type Error = String;
        fn try_from(value: UdpLoadBalancerServiceServersItem) -> Result<Self, String> {
            Ok(Self {
                address: value.address?,
            })
        }
    }
    impl From<super::UdpLoadBalancerServiceServersItem> for UdpLoadBalancerServiceServersItem {
        fn from(value: super::UdpLoadBalancerServiceServersItem) -> Self {
            Self {
                address: Ok(value.address),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct UdpRouter {
        entry_points: Result<Vec<String>, String>,
        service: Result<String, String>,
    }
    impl Default for UdpRouter {
        fn default() -> Self {
            Self {
                entry_points: Ok(Default::default()),
                service: Err("no value supplied for service".to_string()),
            }
        }
    }
    impl UdpRouter {
        pub fn entry_points<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<String>>,
            T::Error: std::fmt::Display,
        {
            self.entry_points = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for entry_points: {}", e));
            self
        }
        pub fn service<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.service = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for service: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<UdpRouter> for super::UdpRouter {
        type Error = String;
        fn try_from(value: UdpRouter) -> Result<Self, String> {
            Ok(Self {
                entry_points: value.entry_points?,
                service: value.service?,
            })
        }
    }
    impl From<super::UdpRouter> for UdpRouter {
        fn from(value: super::UdpRouter) -> Self {
            Self {
                entry_points: Ok(value.entry_points),
                service: Ok(value.service),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct UdpWeightedService {
        services: Result<Vec<super::UdpWeightedServiceServicesItem>, String>,
    }
    impl Default for UdpWeightedService {
        fn default() -> Self {
            Self {
                services: Err("no value supplied for services".to_string()),
            }
        }
    }
    impl UdpWeightedService {
        pub fn services<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<Vec<super::UdpWeightedServiceServicesItem>>,
            T::Error: std::fmt::Display,
        {
            self.services = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for services: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<UdpWeightedService> for super::UdpWeightedService {
        type Error = String;
        fn try_from(value: UdpWeightedService) -> Result<Self, String> {
            Ok(Self {
                services: value.services?,
            })
        }
    }
    impl From<super::UdpWeightedService> for UdpWeightedService {
        fn from(value: super::UdpWeightedService) -> Self {
            Self {
                services: Ok(value.services),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct UdpWeightedServiceServicesItem {
        name: Result<String, String>,
        weight: Result<f64, String>,
    }
    impl Default for UdpWeightedServiceServicesItem {
        fn default() -> Self {
            Self {
                name: Err("no value supplied for name".to_string()),
                weight: Err("no value supplied for weight".to_string()),
            }
        }
    }
    impl UdpWeightedServiceServicesItem {
        pub fn name<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<String>,
            T::Error: std::fmt::Display,
        {
            self.name = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for name: {}", e));
            self
        }
        pub fn weight<T>(mut self, value: T) -> Self
        where
            T: std::convert::TryInto<f64>,
            T::Error: std::fmt::Display,
        {
            self.weight = value
                .try_into()
                .map_err(|e| format!("error converting supplied value for weight: {}", e));
            self
        }
    }
    impl std::convert::TryFrom<UdpWeightedServiceServicesItem>
        for super::UdpWeightedServiceServicesItem
    {
        type Error = String;
        fn try_from(value: UdpWeightedServiceServicesItem) -> Result<Self, String> {
            Ok(Self {
                name: value.name?,
                weight: value.weight?,
            })
        }
    }
    impl From<super::UdpWeightedServiceServicesItem> for UdpWeightedServiceServicesItem {
        fn from(value: super::UdpWeightedServiceServicesItem) -> Self {
            Self {
                name: Ok(value.name),
                weight: Ok(value.weight),
            }
        }
    }
}
pub mod defaults {
    pub(super) fn default_bool<const V: bool>() -> bool {
        V
    }
    pub(super) fn default_i64<T, const V: i64>() -> T
    where
        T: std::convert::TryFrom<i64>,
        <T as std::convert::TryFrom<i64>>::Error: std::fmt::Debug,
    {
        T::try_from(V).unwrap()
    }
    pub(super) fn basic_auth_middleware_realm() -> String {
        "traefik".to_string()
    }
    pub(super) fn digest_auth_middleware_realm() -> String {
        "traefik".to_string()
    }
}
