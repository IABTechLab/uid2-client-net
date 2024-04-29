namespace UID2.Client
{
    public enum DecryptionStatus
    {
        Success,
        NotAuthorizedForMasterKey,
        NotAuthorizedForKey,
        NotInitialized,
        InvalidPayload,
        ExpiredToken,
        KeysNotSynced,
        VersionNotSupported,
        InvalidPayloadType,
        InvalidIdentityScope,
        /// <summary>
        ///  DSPs are still expected to check their records for user opt out, even when this status is not returned
        /// </summary>
        UserOptedOut,
        DomainOrAppNameCheckFailed,
        InvalidTokenLifetime
    }
}
