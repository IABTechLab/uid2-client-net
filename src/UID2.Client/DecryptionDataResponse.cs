using System;

namespace UID2.Client
{
    public struct DecryptionDataResponse
    {
        private readonly DecryptionStatus _status;
        private readonly byte[] _decryptedData;
        private readonly DateTime? _encryptedAt;

        private DecryptionDataResponse(DecryptionStatus status, byte[] decryptedData, DateTime? encryptedAt)
        {
            _status = status;
            _decryptedData = decryptedData;
            _encryptedAt = encryptedAt;
        }

        public static DecryptionDataResponse MakeSuccess(byte[] decryptedData, DateTime encryptedAt)
        {
            return new DecryptionDataResponse(DecryptionStatus.Success, decryptedData, encryptedAt);
        }

        public static DecryptionDataResponse MakeError(DecryptionStatus status)
        {
            return new DecryptionDataResponse(status, null, null);
        }

        public bool Success => _status == DecryptionStatus.Success;
        public DecryptionStatus Status => _status;
        public byte[] DecryptedData => _decryptedData;
        public DateTime? EncryptedAt => _encryptedAt;
    }
}