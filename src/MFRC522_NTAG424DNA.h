/*
 * Arduino RFID/NFC Library for NXP NTAG 424 DNA tags using MFRC522.
 * @author Piotr Obst
 */

#ifndef MFRC522_NTAG424DNA_h
#define MFRC522_NTAG424DNA_h

#include <MFRC522Extended.h>
#include <AES.h>
#include <CBC.h>
#include <AES_CMAC.h>
#include <CRC32.h>

class MFRC522_NTAG424DNA : public MFRC522Extended {

public:
  
  
  /////////////////////////////////////////////////////////////////////////////////////
  // Contructors
  /////////////////////////////////////////////////////////////////////////////////////
  
  
  MFRC522_NTAG424DNA() : MFRC522Extended() {};
  MFRC522_NTAG424DNA(uint8_t rst) : MFRC522Extended(rst) {};
  MFRC522_NTAG424DNA(uint8_t ss, uint8_t rst) : MFRC522Extended(ss, rst) {};
  
  
  enum DNA_StatusCode : byte {
    DNA_STATUS_OK = 0, // Success (and 0x9000, 0x9100 - OPERATION_OK / Successful operaton)
    DNA_STATUS_ERROR = 1, // Error in communication
    DNA_STATUS_COLLISION = 2, // Collission detected
    DNA_STATUS_TIMEOUT = 3, // Timeout in communication.
    DNA_STATUS_NO_ROOM = 4, // A buffer is not big enough.
    DNA_STATUS_INTERNAL_ERROR = 5, // Internal error in the code. Should not happen ;-)
    DNA_STATUS_INVALID = 6, // Invalid argument.
    DNA_STATUS_CRC_WRONG = 7, // The CRC_A does not match
    
    COMMAND_NOT_FOUND = 8, // (910B) - Status used only in Read_Sig.
    COMMAND_FORMAT_ERROR = 9, // (910C) - Status used only in Read_Sig.
    ILLEGAL_COMMAND_CODE = 10, // (911C) Command code not supported.
    INTEGRITY_ERROR = 11, // (911E) CRC or MAC does not match data. Padding bytes not valid.
    NO_SUCH_KEY = 12, // (9140) Invalid key number specified.
    LENGTH_ERROR = 13, // (6700, 917E) Length of command string invalid.
    PERMISSION_DENIED = 14, // (919D) Current configuration / status does not allow the requested command.
    PARAMETER_ERROR = 15, // (919E) Value of the parameter(s) invalid.
    AUTHENTICATION_DELAY = 16, // (91AD) Currently not allowed to authenticate. Keep trying until full delay is spent.
    AUTHENTICATION_ERROR = 17, // (91AE) Current authentication status does not allow the requested command.
    ADDITIONAL_FRAME = 18, // (91AF) Additionaldata frame is expected to be sent.
    BOUNDARY_ERROR = 19, // (91BE) Attempt to read/write data from/to beyond the file's/record's limits. Attempt to exceed the limits of a value file.
    COMMAND_ABORTED = 20, // (91CA) Previous Command was not fully completed. Not all Frames were requested or provided by the PCD.
    MEMORY_ERROR = 21, // (6581, 91EE) Failure when reading or writing to non-volatile memory.
    FILE_NOT_FOUND = 22, // (91F0) Specified file number does not exist.
    SECURITY_NOT_SATISFIED = 23, // (6982) Security status not satisfied.
    CONDITIONS_NOT_SATISFIED = 24, // (6985) Conditions of use not satisfied.
    FILE_OR_APP_NOT_FOUND = 25, // (6A82) File or application not found.
    INCORRECT_PARAMS = 26, // (6A86) Incorrect parameters P1-P2.
    INCORRECT_LC = 27, // (6A87) Lc inconsistent with parameters P1-P2.
    CLA_NOT_SUPPORTED = 28, // (6E00) CLA not supported
    
    DNA_WRONG_RESPONSE_LEN = 29,
    DNA_WRONG_RESPONSE_CMAC = 30,
    DNA_WRONG_RNDA = 31,
    DNA_CMD_CTR_OVERFLOW = 32,
    DNA_UNKNOWN_ERROR = 33,
    DNA_SDM_NOT_IMPLEMENTED_IN_LIB = 34,
    
    DNA_STATUS_MIFARE_NACK = 0xff // A MIFARE PICC responded with NAK.
  };
  
  
  enum DNA_File : byte {
    DNA_FILE_CC = 0x01,
    DNA_FILE_NDEF = 0x02,
    DNA_FILE_PROPRIETARY = 0x03
  };
  
  
  enum DNA_CommMode : byte {
    DNA_COMMMODE_PLAIN = 0x00, // 0b00, but can be 0b10 (0x02) as well
    DNA_COMMMODE_MAC = 0x01, // 0b01
    DNA_COMMMODE_FULL = 0x03 // 0b11
  };
  
  
  byte CmdCtr[2] = {0x00, 0x00};
  
  
  byte SesAuthEncKey[16];
  byte SesAuthMacKey[16];
  byte TI[4];
  
  
  // File contents at delivery:
  // byte CC_FILE_AT_DELIVERY[32] = {0x00, 0x17, 0x20, 0x01, 0x00, 0x00, 0xFF, 0x04, 0x06, 0xE1, 0x04, 0x01, 0x00, 0x00, 0x00, 0x05, 0x06, 0xE1, 0x05, 0x00, 0x80, 0x82, 0x83};
  // byte NDEF_FILE_AT_DELIVERY[256] = {0x00}; // 256 zeros
  // byte PROPRIETARY_FILE_AT_DELIVERY[128] = {0x00, 0x7E}; // 0x00, 0x7E followed by 126 zeros
  
  
  /////////////////////////////////////////////////////////////////////////////////////
  //
  // Basic functions for communicating with NTAG 424 DNA cards
  //
  /////////////////////////////////////////////////////////////////////////////////////
  
  
  StatusCode DNA_BasicTransceive(byte* sendData, byte sendLen, byte* backData, byte* backLen, byte pcb = 2);
  
  DNA_StatusCode DNA_AuthenticateEV2First(byte keyNumber, byte* key, byte* rndA);
  
  DNA_StatusCode DNA_AuthenticateEV2NonFirst(byte keyNumber, byte* key, byte* rndA);
  
  //DNA_AuthenticateLRPFirst - not implemented
  
  //DNA_AuthenticateLRPNonFirst - not implemented
  
  
  /////////////////////////////////////////////////////////////////////////////////////
  //
  // Plain communication mode
  //
  /////////////////////////////////////////////////////////////////////////////////////
  
  
  // Warning! "SDMEnabled = false" disables SDM for a file!
  // Use this function if you do not need to use SDM (SDM is disabled by default on a new tag).
  DNA_StatusCode DNA_Plain_ChangeFileSettings(DNA_File file, DNA_CommMode commMode, byte readAccess, byte writeAccess, byte readWriteAccess, byte changeAccess, byte SDMEnabled);
  
  // sendData = FileOption, AccessRights(2), [SDMOptions], [SMDAccessRights(2)], [UIDOffset(3)], [SDMReadCtrOffset(3)],
  // [PICCDataOffset(3)], [SDMMACInputOFFset(3)], [SDMENCOffset(3)], [SDMENCLength(3)], [SDMMACOffset(3)], [SDMReadCtrLimit(3)]
  // Note: arguments in brackets are optional
  // Use this function only if you want to use SDM and know what you are doing.
  DNA_StatusCode DNA_Plain_ChangeFileSettings(DNA_File file, byte* sendData, byte sendDataLen);
  
  // Reads UID when random ID is not enabled.
  // If random ID is enabled, reads random ID. To read the true ID in that case, use DNA_Full_GetCardUID.
  // This is only a wrapper function. It gets uid.uidByte from MFRC522 lib.
  void DNA_Plain_GetCardUID(byte* backUID_7B);
  
  DNA_StatusCode DNA_Plain_GetFileSettings(DNA_File file, byte* backRespData, byte* backRespLen);
  
  DNA_StatusCode DNA_Plain_GetFileSettings_AccessRights(DNA_File file, byte* backReadAccess, byte* backWriteAccess, byte* backReadWriteAccess, byte* backChangeAccess);
  
  DNA_StatusCode DNA_Plain_GetFileSettings_CommMode(DNA_File file, DNA_CommMode* backCommMode);
  
  DNA_StatusCode DNA_Plain_GetFileSettings_SDM(DNA_File file, bool* backSDMEnabled);
  
  // Writes to backRespData 28 or 29 bytes according to tables 54, 56 and 58 from NT4H2421Gx (NTAG 424 DNA) datasheet:
  // VendorID, HWType, HWSubType, HWMajorVersion, HWMinorVersion, HWStorageSize, HWProtocol,
  // VendorID, SWType, SWSubType, SWMajorVersion, SWMinorVersion, SWStorageSize, SWProtocol,
  // UID(7), BatchNo(4), BatchNo/FabKey, FabKey/CWProd, YearProd, [FabKeyID]
  // Note: arguments in brackets are optional; SW1 and SW2 are not included in backRespData
  DNA_StatusCode DNA_Plain_GetVersion(byte* backRespData, byte* backRespLen);
  
  // Data read in 59 B blocks
  DNA_StatusCode DNA_Plain_ISOReadBinary(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen);
  
  DNA_StatusCode DNA_Plain_ISOSelectFile(byte* fileIdentifier);
  
  DNA_StatusCode DNA_Plain_ISOSelectFile_Application();
  
  DNA_StatusCode DNA_Plain_ISOSelectFile_PICC();
  
  // Data written in 59 B blocks
  DNA_StatusCode DNA_Plain_ISOUpdateBinary(DNA_File file, uint16_t length, byte offset, byte* sendData);
  
  // Data read in 59 B blocks
  DNA_StatusCode DNA_Plain_ReadData(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen);
  
  // DNA_Plain_Read_Sig only reads, but does not verify the signature.
  // Due to license terms, the code for Sig verification cannot be included in this library.
  // See https://www.nxp.com/confidential/AN11350 and
  // https://community.nxp.com/t5/NFC-Knowledge-Base/Demo-for-Originality-Signature-Verification/ta-p/1278669
  // Full_Read_Sig is not implemented, because response in Full is 74 B, but MFRC522 can only handle 61 B responses, so it can't be implemented. If at least 64 B were available, it would be possible.
  DNA_StatusCode DNA_Plain_Read_Sig(byte* backSignature);
  
  // Data written in 50 B blocks
  DNA_StatusCode DNA_Plain_WriteData(DNA_File file, uint16_t length, byte offset, byte* sendData);
  
  
  /////////////////////////////////////////////////////////////////////////////////////
  //
  // Mac communication mode (prior DNA_AuthenticateEV2 required)
  //
  /////////////////////////////////////////////////////////////////////////////////////
  
  
  // Writes to backRespData 7 to 34 bytes according to table 73 from NT4H2421Gx (NTAG 424 DNA) datasheet:
  // FileType, FileOption, AccessRights(2), FileSize(3), [SDMOptions], [SDMAccessRights(2)], [UIDOffset(3)], [SDMReadCtrOffset(3)],
  // [PICCDataOffset(3)], [PICCDataOffset(3)], [SDMENCOffset(3)], [SDMENCLength(3)], [SDMMACOffset(3)], [SDMReadCtrLimit(3)]
  // Note: arguments in brackets are optional; SW1 and SW2 are not included in backRespData
  DNA_StatusCode DNA_Mac_GetFileSettings(DNA_File file, byte* backRespData, byte* backRespLen);
  
  DNA_StatusCode DNA_Mac_GetFileSettings_AccessRights(DNA_File file, byte* backReadAccess, byte* backWriteAccess, byte* backReadWriteAccess, byte* backChangeAccess);
  
  DNA_StatusCode DNA_Mac_GetFileSettings_CommMode(DNA_File file, DNA_CommMode* backCommMode);
  
  DNA_StatusCode DNA_Mac_GetFileSettings_SDM(DNA_File file, bool* backSDMEnabled);
  
  DNA_StatusCode DNA_Mac_GetKeyVersion(byte keyNumber, byte* backKeyVersion);
  
  // Writes to backRespData 28 or 29 bytes according to tables 54, 56 and 58 from NT4H2421Gx (NTAG 424 DNA) datasheet:
  // VendorID, HWType, HWSubType, HWMajorVersion, HWMinorVersion, HWStorageSize, HWProtocol,
  // VendorID, SWType, SWSubType, SWMajorVersion, SWMinorVersion, SWStorageSize, SWProtocol,
  // UID(7), BatchNo(4), BatchNo/FabKey, FabKey/CWProd, YearProd, [FabKeyID]
  // Note: arguments in brackets are optional; SW1 and SW2 are not included in backRespData
  DNA_StatusCode DNA_Mac_GetVersion(byte* backRespData, byte* backRespLen);
  
  // Data read in 51 B blocks
  DNA_StatusCode DNA_Mac_ReadData(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen);
  
  // Data written in 41 B blocks
  DNA_StatusCode DNA_Mac_WriteData(DNA_File file, uint16_t length, byte offset, byte* sendData);
  
  
  /////////////////////////////////////////////////////////////////////////////////////
  //
  // Full communication mode (prior DNA_AuthenticateEV2 required)
  //
  /////////////////////////////////////////////////////////////////////////////////////
  
  
  // Warning! "SDMEnabled = false" disables SDM for a file!
  // Use this function if you do not need to use SDM (SDM is disabled by default on a new tag).
  DNA_StatusCode DNA_Full_ChangeFileSettings(DNA_File file, DNA_CommMode commMode, byte readAccess, byte writeAccess, byte readWriteAccess, byte changeAccess, byte SDMEnabled);
  
  // sendData = FileOption, AccessRights(2), [SDMOptions], [SMDAccessRights(2)], [UIDOffset(3)], [SDMReadCtrOffset(3)],
  // [PICCDataOffset(3)], [SDMMACInputOFFset(3)], [SDMENCOffset(3)], [SDMENCLength(3)], [SDMMACOffset(3)], [SDMReadCtrLimit(3)]
  // Note: arguments in brackets are optional
  // Use this function only if you want to use SDM and know what you are doing.
  DNA_StatusCode DNA_Full_ChangeFileSettings(DNA_File file, byte* sendData, byte sendDataLen);
  
  DNA_StatusCode DNA_Full_ChangeKey(byte keyNumber, byte* oldKey, byte* newKey, byte newKeyVersion);
  
  DNA_StatusCode DNA_Full_ChangeKey0(byte* newKey, byte newKeyVersion);
  
  DNA_StatusCode DNA_Full_GetCardUID(byte* backUID_7B);
  
  // Reads SDMReadCtr. This command works if you enable SDM on your own, but it is not implemented in this library currently.
  DNA_StatusCode DNA_Full_GetFileCounters(DNA_File file, uint32_t* backSDMReadCtr);
  
  // Data read in 47 B blocks
  DNA_StatusCode DNA_Full_ReadData(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen);
  
  // Response from Full_Read_Sig is 74 B, but MFRC522 can only handle 61 B responses, so it can't be implemented. If at least 64 B were available, it would be possible.
  // See DNA_Plain_Read_Sig
  //DNA_StatusCode DNA_Full_Read_Sig - not implemented (MFRC522 hardware limitation)
  
  DNA_StatusCode DNA_Full_SetConfiguration(byte* sendData, byte sendDataLen);
  
  DNA_StatusCode DNA_Full_SetConfiguration_FailedCtrOption(bool FailedCtrEnabled, uint16_t TotFailCtrLimit, uint16_t TotFailCtrDecr);
  
  // Warning! Enables LRP (unsuported by this lib) permanently, when "turnLRPModeON_Permanent = true"! Use with care.
  DNA_StatusCode DNA_Full_SetConfiguration_PDCap2(bool turnLRPModeON_Permanent, byte PDCap2_5, byte PDCap2_6);
  
  // Warning! Enables RandomID permanently! Use with care.
  DNA_StatusCode DNA_Full_SetConfiguration_Permanent_RandomID_ON();
  
  // Warning! Disables SDM chained writing permanently! Use with care.
  DNA_StatusCode DNA_Full_SetConfiguration_Permanent_SDM_Chained_Write_OFF();
  
  // Warning! It is strongly recommended not to disable StrongBackModulation!
  DNA_StatusCode DNA_Full_SetConfiguration_StrongBackModulation(bool StrongBackModulation);
  
  // Data written in 31 B blocks
  DNA_StatusCode DNA_Full_WriteData(DNA_File file, uint16_t length, byte offset, byte* sendData);
  
  
  /////////////////////////////////////////////////////////////////////////////////////
  //
  // Helper functions
  //
  /////////////////////////////////////////////////////////////////////////////////////
  
  
  // Deselects current card and returns true if any card responds to a WakeupA command.
  bool PICC_TryDeselectAndWakeupA();
  
protected:
  
  /////////////////////////////////////////////////////////////////////////////////////
  //
  // Protected functions
  //
  /////////////////////////////////////////////////////////////////////////////////////
  
  StatusCode DNA_AuthenticateEV2First_Part1(byte keyNumber, byte* backData, byte* backLen);
  StatusCode DNA_AuthenticateEV2First_Part2(byte* inData, byte* backData, byte* backLen);
  StatusCode DNA_AuthenticateEV2NonFirst_Part1(byte keyNumber, byte* backData, byte* backLen);
  StatusCode DNA_AuthenticateEV2NonFirst_Part2(byte* inData, byte* backData, byte* backLen);
  
  DNA_StatusCode DNA_Plain_GetVersion_native(byte Cmd, byte expectedSV2, byte* backRespData, byte* backRespLen);
  DNA_StatusCode DNA_Plain_ISOReadBinary_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen);
  DNA_StatusCode DNA_Plain_ISOUpdateBinary_native(DNA_File file, byte length, byte offset, byte* sendData);
  DNA_StatusCode DNA_Plain_ReadData_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen);
  DNA_StatusCode DNA_Plain_WriteData_native(DNA_File file, byte length, byte offset, byte* sendData);
  
  DNA_StatusCode DNA_Mac_GetVersion_native(byte Cmd, byte expectedSV2, byte* backRespData, byte* backRespLen);
  DNA_StatusCode DNA_Mac_ReadData_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen);
  DNA_StatusCode DNA_Mac_WriteData_native(DNA_File file, byte length, byte offset, byte* sendData);
  
  DNA_StatusCode DNA_Full_ReadData_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen);
  DNA_StatusCode DNA_Full_WriteData_native(DNA_File file, byte length, byte offset, byte* sendData);
  
  DNA_StatusCode DNA_CheckResponseCMACt(byte* responseCMACt);
  DNA_StatusCode DNA_CheckResponseCMACtWithData(byte* data, byte dataLen, byte* responseCMACt);
  DNA_StatusCode DNA_InterpretErrorCode(byte* SW1_2);
  bool DNA_IncrementCmdCtr();
  void DNA_CalculateCMACt(byte* CMACInput, byte CMACInputSize, byte* backCMACt);
  void DNA_CalculateCMACtNoData(byte Cmd, byte* CmdHeader, byte CmdHeaderLen, byte* backCMACt);
  void DNA_CalculateCRC32NK(byte* message16, byte* backCRC);
  void DNA_CalculateDataEncAndCMACt(byte Cmd, byte* dataToEnc, byte dataToEncLen, byte* CmdHeader, byte CmdHeaderLen, byte* backDataEncAndCMACt);
  void DNA_CalculateIV(byte b0, byte b1, byte* backIV);
  void DNA_CalculateIVCmd(byte* backIVCmd);
  void DNA_CalculateIVResp(byte* backIVResp);
  void DNA_GenerateSesAuthKeys(byte* authKey, byte* RndA, byte* RndB);
  void DNA_CalculateSV(byte b0, byte b1, byte* RndA, byte* RndB, byte* backSV);
  void DNA_CalculateSV1(byte* RndA, byte* RndB, byte* backSV1);
  void DNA_CalculateSV2(byte* RndA, byte* RndB, byte* backSV2);
  
};

#endif
