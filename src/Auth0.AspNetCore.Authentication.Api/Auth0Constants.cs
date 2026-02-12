namespace Auth0.AspNetCore.Authentication.Api;

/// <summary>
///     Provides a container for Auth0-specific constant values that are used throughout the SDK.
/// </summary>
public static class Auth0Constants
{
    public static class AuthenticationScheme
    {
        public const string Auth0 = "Auth0";
        public const string Bearer = "Bearer ";
    }

    public static class DPoP
    {
        public const int IatOffsetDefault = 300;
        public const int LeewayDefault = 30;
        public const string AuthenticationScheme = "DPoP ";
        public const string ProofHeader = "DPoP";
        public const string JsonWebKey = "jwk";
        public const string Cnf = "cnf";
        public const string JwkThumbprint = "jkt";
        public const string Ath = "ath";
        public const string Jti = "jti";
        public const string Htm = "htm";
        public const string Htu = "htu";
        public const string Iat = "iat";
        public const string JwtTyp = "dpop+jwt";

        public const string BearerErrorCode = "BearerErrorCode";
        public const string BearerErrorDescription = "BearerErrorDescription";
        public const string BearerStatusCode = "BearerStatusCode";

        public const string DPoPErrorCode = "DPoPErrorCode";
        public const string DPoPErrorDescription = "DPoPErrorDescription";
        public const string DPoPStatusCode = "DPoPStatusCode";

        public const string WWWAuthenticateHeader = "WWW-Authenticate";

        public abstract class Error
        {
            public const string BearerScheme = "Bearer";
            public const string DPoPScheme = "DPoP";
            public const string DefaultDPoPAlgs = "algs=\"ES256\"";
            public const string DefaultRealm = "realm=\"api\"";
            public abstract class Code
            {
                public const string InvalidToken = "invalid_token";
                public const string InvalidRequest = "invalid_request";
                public const string InvalidDPoPProof = "invalid_dpop_proof";
            }

            public abstract class Description
            {
                public const string BearerSchemeWithDPoPProof = "DPoP-bound token requires the DPoP authentication scheme, not Bearer";
                public const string DPoPProofValidationFailure = "Failed to verify DPoP proof";
                public const string DPoPProofMissing = "DPoP proof token is missing.";
                public const string AccessTokenMissing = "Access token is missing.";
                public const string CnfClaimMissing = "JWT Access token has no jkt confirmation claim";
                public const string InvalidCnfClaim = "JWT Access token has invalid cnf confirmation claim";
                public const string InvalidSignature = "Signature verification failed";
                public const string UnknownError = "Unknown error";
            }
        }
    }

    public static class CustomDomains
    {
        public static class Error
        {
            public static class Description
            {
                public const string InvalidIssuer = "Token issuer is invalid or missing";
                public const string IssuerNotAllowed = "Token issuer is not in the allowed list";
                public const string ConfigurationFailed = "Failed to retrieve OIDC configuration";
                public const string SymmetricAlgorithm = "Symmetric algorithms are not supported";
                public const string ConfigurationConflict = "Cannot configure both Domains and DomainsResolver";
                public const string InvalidToken = "Token invalid or missing";
            }
        }
    }
}
