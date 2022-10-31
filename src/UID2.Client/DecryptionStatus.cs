namespace UID2.Client
{
    public enum DecryptionStatus
    {
        Success,
        NotAuthorizedForKey,
        NotInitialized,
        InvalidPayload,
        ExpiredToken,
        KeysNotSynced,
        VersionNotSupported,
        InvalidPayloadType,
        InvalidIdentityScope,
    }
}
