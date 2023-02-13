namespace UID2.Client
{
    public enum EncryptionStatus
    {
        Success,
        NotAuthorizedForKey,
        NotAuthorizedForMasterKey,
        NotInitialized,
        KeysNotSynced,
        TokenDecryptFailure,
        KeyInactive,
        EncryptionFailure,
    }
}
