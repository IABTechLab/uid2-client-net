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
        InvalidIdentityType,
    }
}
