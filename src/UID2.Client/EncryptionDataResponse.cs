using System;

namespace UID2.Client
{
    public struct EncryptionDataResponse
    {
        private readonly EncryptionStatus _status;
        private readonly string _encryptedData;

        private EncryptionDataResponse(EncryptionStatus status, string encryptedData)
        {
            _status = status;
            _encryptedData = encryptedData;
        }

        public static EncryptionDataResponse MakeSuccess(string encryptedData)
        {
            return new EncryptionDataResponse(EncryptionStatus.Success, encryptedData);
        }

        public static EncryptionDataResponse MakeError(EncryptionStatus status)
        {
            return new EncryptionDataResponse(status, null);
        }

        public bool Success => _status == EncryptionStatus.Success;
        public EncryptionStatus Status => _status;
        public string EncryptedData=> _encryptedData;
    }
}
