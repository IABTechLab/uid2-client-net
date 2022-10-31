namespace UID2.Client
{
    public enum EncryptionStatus
    {
        Success,
        NotAuthorizedForKey,
        NotInitialized,
        KeysNotSynced,
        TokenDecryptFailure,
        KeyInactive,
        EncryptionFailure,
    }
}
