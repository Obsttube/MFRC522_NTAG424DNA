/*
 * Arduino RFID/NFC Library for NXP NTAG 424 DNA tags using MFRC522.
 * NOTE: Please also check the comments in MFRC522_NTAG424DNA.h
 * @author Piotr Obst
 */

#include "MFRC522_NTAG424DNA.h"


CBC<AES128> cbc;
AESTiny128 aes128;
AES_CMAC cmac(aes128);


/////////////////////////////////////////////////////////////////////////////////////
//
// Basic functions for communicating with NTAG 424 DNA cards
//
/////////////////////////////////////////////////////////////////////////////////////


MFRC522Extended::StatusCode MFRC522_NTAG424DNA::DNA_BasicTransceive(byte* sendData, byte sendLen, byte* backData, byte* backLen, byte pcb)
{
  MFRC522Extended::StatusCode result;
  
  PcbBlock sendBlock;
  sendBlock.prologue.pcb = pcb;
  sendBlock.inf.size = sendLen;
  sendBlock.inf.data = sendData;
  
  PcbBlock backBlock;
  backBlock.inf.size = *backLen;
  backBlock.inf.data = backData;
  
  result = TCL_Transceive(&sendBlock, &backBlock);
  
  *backLen=backBlock.inf.size;
  
  return result;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_AuthenticateEV2First(byte keyNumber, byte* key, byte* rndA)
{
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_AuthenticateEV2First_Part1(keyNumber, backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0xAF)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 18)
    return DNA_WRONG_RESPONSE_LEN;
  
  byte iv[16] = {0};
  byte decryptedRndB[16];
  cbc.setKey(key, 16);
  cbc.setIV(iv, 16);
  
  cbc.decrypt(decryptedRndB, backData, 16);
  
  byte shiftedRndB[16];
  
  // shift RndB left
  for(byte i = 0; i < 15; i++){
    shiftedRndB[i] = decryptedRndB[i + 1];
  }
  shiftedRndB[15] = decryptedRndB[0];
  
  byte inData[32];
  memcpy(inData, rndA, 16);
  memcpy(&inData[16], shiftedRndB, 16);
  
  byte inDataEncrypted[32];
  cbc.setIV(iv, 16);
  cbc.encrypt(inDataEncrypted, inData, 32);
  
  backLen = 61;
  statusCode = DNA_AuthenticateEV2First_Part2(inDataEncrypted, backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 34)
    return DNA_WRONG_RESPONSE_LEN;
  
  byte decryptedPart2[32];
  cbc.setIV(iv, 16);
  cbc.decrypt(decryptedPart2, backData, 32);
  
  // compare sent RndA with received RndA'
  for(byte i = 0; i < 15; i++)
  {
    if(decryptedPart2[i + 4] != rndA[i + 1])
      return DNA_WRONG_RNDA;
  }
  
  if(decryptedPart2[19] != rndA[0])
    return DNA_WRONG_RNDA;
  
  memcpy(TI, decryptedPart2, 4);
  
  CmdCtr[0] = 0;
  CmdCtr[1] = 0;
  
  DNA_GenerateSesAuthKeys(key, rndA, decryptedRndB);
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_AuthenticateEV2NonFirst(byte keyNumber, byte* key, byte* rndA)
{
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_AuthenticateEV2NonFirst_Part1(keyNumber, backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0xAF)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 18)
    return DNA_WRONG_RESPONSE_LEN;
  
  byte iv[16] = {0};
  byte decryptedRndB[16];
  cbc.setKey(key, 16);
  cbc.setIV(iv, 16);
  
  cbc.decrypt(decryptedRndB, backData, 16);
  
  byte shiftedRndB[16];
  
  // shift RndB left
  for(byte i = 0; i < 15; i++){
    shiftedRndB[i] = decryptedRndB[i + 1];
  }
  shiftedRndB[15] = decryptedRndB[0];
  
  byte inData[32];
  memcpy(inData, rndA, 16);
  memcpy(&inData[16], shiftedRndB, 16);
  
  byte inDataEncrypted[32];
  cbc.setIV(iv, 16);
  cbc.encrypt(inDataEncrypted, inData, 32);
  
  backLen = 61;
  statusCode = DNA_AuthenticateEV2NonFirst_Part2(inDataEncrypted, backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 18)
    return DNA_WRONG_RESPONSE_LEN;
  
  byte decryptedPart2[16];
  cbc.setIV(iv, 16);
  cbc.decrypt(decryptedPart2, backData, 16);
  
  // compare sent RndA with received RndA'
  for(byte i = 0; i < 15; i++)
  {
    if(decryptedPart2[i] != rndA[i + 1])
      return DNA_WRONG_RNDA;
  }
  
  if(decryptedPart2[15] != rndA[0])
    return DNA_WRONG_RNDA;
  
  DNA_GenerateSesAuthKeys(key, rndA, decryptedRndB);
  
  return DNA_STATUS_OK;
}






/////////////////////////////////////////////////////////////////////////////////////
//
// Plain communication mode
//
/////////////////////////////////////////////////////////////////////////////////////


// Warning! "SDMEnabled = false" disables SDM for a file!
// Use this function if you do not need to use SDM (SDM is disabled by default on a new tag).
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ChangeFileSettings(DNA_File file, DNA_CommMode commMode, byte readAccess, byte writeAccess, byte readWriteAccess, byte changeAccess, byte SDMEnabled)
{
  if(SDMEnabled)
    return DNA_SDM_NOT_IMPLEMENTED_IN_LIB;
  
  byte sendData[3];
  
  sendData[0] = commMode;
  sendData[1] = (readWriteAccess << 4) | changeAccess;
  sendData[2] = (readAccess << 4) | writeAccess;
  
  return DNA_Plain_ChangeFileSettings(file, sendData, 3);
}


// sendData = FileOption, AccessRights(2), [SDMOptions], [SMDAccessRights(2)], [UIDOffset(3)], [SDMReadCtrOffset(3)],
// [PICCDataOffset(3)], [SDMMACInputOFFset(3)], [SDMENCOffset(3)], [SDMENCLength(3)], [SDMMACOffset(3)], [SDMReadCtrLimit(3)]
// Note: arguments in brackets are optional
// Use this function only if you want to use SDM and know what you are doing.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ChangeFileSettings(DNA_File file, byte* sendData, byte sendDataLen)
{
  if(sendDataLen > 30)
    return DNA_STATUS_NO_ROOM;
  
  byte* sendData2 = new byte[sendDataLen + 7];
  
  sendData2[0] = 0x90; // CLA
  sendData2[1] = 0x5F; // CMD
  sendData2[2] = 0x00; // P1
  sendData2[3] = 0x00; // P2
  sendData2[4] = sendDataLen + 1; // Lc
  sendData2[5] = file; // FileNo
  memcpy(&sendData2[6], sendData, sendDataLen);
  sendData2[6 + sendDataLen] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, sendDataLen + 7, backData, &backLen);
  
  delete[] sendData2;
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if(backLen != 2)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_STATUS_OK;
}


// Reads UID when random ID is not enabled.
// If random ID is enabled, reads random ID. To read the true ID in that case, use DNA_Full_GetCardUID.
// This is only a wrapper function. It gets uid.uidByte from MFRC522 lib.
void MFRC522_NTAG424DNA::DNA_Plain_GetCardUID(byte* backUID_7B)
{
  memcpy(backUID_7B, uid.uidByte, 7);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_GetFileSettings(DNA_File file, byte* backRespData, byte* backRespLen)
{
  byte sendData[7];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = 0xF5; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x01; // Lc
  sendData[5] = file; // FileNo
  sendData[6] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if(backLen < 9 || backLen > 36)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (*backRespLen < backLen - 2)
    return DNA_STATUS_NO_ROOM;
  
  memcpy(backRespData, backData, backLen - 2);
  *backRespLen = backLen - 2;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_GetFileSettings_AccessRights(DNA_File file, byte* backReadAccess, byte* backWriteAccess, byte* backReadWriteAccess, byte* backChangeAccess)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  byte backRespData[34];
  byte backRespLen = 34;
  dna_statusCode = DNA_Plain_GetFileSettings(file, backRespData, &backRespLen);
  
  if(dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  *backReadAccess = backRespData[3] >> 4;
  *backWriteAccess = backRespData[3] & 0b1111;
  *backReadWriteAccess = backRespData[2] >> 4;
  *backChangeAccess = backRespData[2] & 0b1111;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_GetFileSettings_CommMode(DNA_File file, DNA_CommMode* backCommMode)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  byte backRespData[34];
  byte backRespLen = 34;
  dna_statusCode = DNA_Plain_GetFileSettings(file, backRespData, &backRespLen);
  
  if(dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if((backRespData[1] & 0b11) == 0b10)
    *backCommMode = DNA_COMMMODE_PLAIN;
  else
    *backCommMode = DNA_CommMode(backRespData[1] & 0b11);
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_GetFileSettings_SDM(DNA_File file, bool* backSDMEnabled)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  byte backRespData[34];
  byte backRespLen = 34;
  dna_statusCode = DNA_Plain_GetFileSettings(file, backRespData, &backRespLen);
  
  if(dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  *backSDMEnabled = backRespData[1] & 0b01000000;
  
  return DNA_STATUS_OK;
}


// Writes to backRespData 28 or 29 bytes according to tables 54, 56, 58 from NT4H2421Gx (NTAG 424 DNA) datasheet:
// VendorID, HWType, HWSubType, HWMajorVersion, HWMinorVersion, HWStorageSize, HWProtocol,
// VendorID, SWType, SWSubType, SWMajorVersion, SWMinorVersion, SWStorageSize, SWProtocol,
// UID(7), BatchNo(4), BatchNo/FabKey, FabKey/CWProd, YearProd, [FabKeyID]
// Note: arguments in brackets are optional; SW1 and SW2 are not included in backRespData
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_GetVersion(byte* backRespData, byte* backRespLen)
{
  byte backData[29];
  byte backLen;
  
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  dna_statusCode = DNA_Plain_GetVersion_native(0x60, 0xAF, backData, &backLen);
  
  if (dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if(backLen != 7)
    return DNA_WRONG_RESPONSE_LEN;
  
  
  dna_statusCode = DNA_Plain_GetVersion_native(0xAF, 0xAF, &backData[7], &backLen);
  
  if (dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if(backLen != 7)
    return DNA_WRONG_RESPONSE_LEN;
  
  
  dna_statusCode = DNA_Plain_GetVersion_native(0xAF, 0x00, &backData[14], &backLen);
  
  if (dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if(backLen != 14 && backLen != 15)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (*backRespLen < backLen + 14)
    return DNA_STATUS_NO_ROOM;
  
  memcpy(backRespData, backData, backLen + 14);
  *backRespLen = backLen + 14;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOReadBinary(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  
  byte* finalBackData = new byte[length];
  uint16_t finalBackLen = 0;
  
  byte backLen = 59;
  if(length < 59)
    backLen = length;
  byte* backData = new byte[backLen];
  
  while (length > 59)
  {
    dna_statusCode = DNA_Plain_ISOReadBinary_native(file, 59, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    offset += 59;
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
    
    if (backLen < 59)
      length = 0;
    else
      length -= 59;
    backLen = 59;
  }
  
  if (length > 0)
  {
    dna_statusCode = DNA_Plain_ISOReadBinary_native(file, length, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
  }
  
  delete[] backData;
  
  if (*backReadLen < finalBackLen)
  {
    delete[] finalBackData;
    return DNA_STATUS_NO_ROOM;
  }
  
  memcpy(backReadData, finalBackData, finalBackLen);
  delete[] finalBackData;
  *backReadLen = finalBackLen;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOSelectFile(byte* fileIdentifier)
{  
  byte sendData[8];
  
  sendData[0] = 0; // CLA
  sendData[1] = 0xA4; // CMD
  sendData[2] = 0; // P1
  sendData[3] = 0x0C; // P2
  sendData[4] = 0x02; // Lc
  sendData[5] = fileIdentifier[0];
  sendData[6] = fileIdentifier[1];
  sendData[7] = 0; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  StatusCode statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backLen < 2)
      return DNA_WRONG_RESPONSE_LEN;
  
  if (backData[backLen - 2] != 0x90 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOSelectFile_Application()
{
  byte fileIdentifier[2] = {0xE1, 0x10};
  return DNA_Plain_ISOSelectFile(fileIdentifier);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOSelectFile_PICC()
{
  byte fileIdentifier[2] = {0x3F, 0x00};
  return DNA_Plain_ISOSelectFile(fileIdentifier);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOUpdateBinary(DNA_File file, uint16_t length, byte offset, byte* sendData)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  uint16_t sendDataOffset = 0;
  
  while (length > 58)
  {
    dna_statusCode = DNA_Plain_ISOUpdateBinary_native(file, 58, offset, &sendData[sendDataOffset]);
    if (dna_statusCode != DNA_STATUS_OK)
      return dna_statusCode;
    
    offset += 58;
    sendDataOffset += 58;
    length -= 58;
  }
  
  if (length == 0)
    return DNA_STATUS_OK;
  
  return DNA_Plain_ISOUpdateBinary_native(file, length, offset, &sendData[sendDataOffset]);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ReadData(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  
  byte* finalBackData = new byte[length];
  uint16_t finalBackLen = 0;
  
  byte backLen = 59;
  if(length < 59)
    backLen = length;
  byte* backData = new byte[backLen];
  
  while (length > 59)
  {
    dna_statusCode = DNA_Plain_ReadData_native(file, 59, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    offset += 59;
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
    
    if (backLen < 59)
      length = 0;
    else
      length -= 59;
    backLen = 59;
  }
  
  if (length > 0)
  {
    dna_statusCode = DNA_Plain_ReadData_native(file, length, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
  }
  
  delete[] backData;
  
  if (*backReadLen < finalBackLen)
  {
    delete[] finalBackData;
    return DNA_STATUS_NO_ROOM;
  }
  
  memcpy(backReadData, finalBackData, finalBackLen);
  delete[] finalBackData;
  *backReadLen = finalBackLen;
  
  return DNA_STATUS_OK;
}


// DNA_Plain_Read_Sig only reads, but does not verify the signature.
// Due to license terms, the code for Sig verification cannot be included in this library.
// See https://www.nxp.com/confidential/AN11350 and
// https://community.nxp.com/t5/NFC-Knowledge-Base/Demo-for-Originality-Signature-Verification/ta-p/1278669
// Full_Read_Sig is not implemented, because response in Full is 74 B, but MFRC522 can only handle 61 B responses, so it can't be implemented. If at least 64 B were available, it would be possible.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_Read_Sig(byte* backSignature)
{
  byte sendData[7];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = 0x3C; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x01; // Lc
  sendData[5] = 0x00; // Data (name is misleading, it is a part of HEADER not a part of data)
  sendData[6] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  // datasheet says it should be 0x9100, but it is 0x9190, which application note seems to confirm
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x90)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 58)
    return DNA_WRONG_RESPONSE_LEN;
    
  memcpy(backSignature, backData, 56);
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_WriteData(DNA_File file, uint16_t length, byte offset, byte* sendData)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  uint16_t sendDataOffset = 0;
  
  while (length > 50)
  {
    dna_statusCode = DNA_Plain_WriteData_native(file, 50, offset, &sendData[sendDataOffset]);
    if (dna_statusCode != DNA_STATUS_OK)
      return dna_statusCode;
    
    offset += 50;
    sendDataOffset += 50;
    length -= 50;
  }
  
  if (length == 0)
    return DNA_STATUS_OK;
  
  return DNA_Plain_WriteData_native(file, length, offset, &sendData[sendDataOffset]);
}






/////////////////////////////////////////////////////////////////////////////////////
//
// Mac communication mode (prior DNA_AuthenticateEV2 required)
//
/////////////////////////////////////////////////////////////////////////////////////


// Writes to backRespData 7 to 34 bytes according to table 73 from NT4H2421Gx (NTAG 424 DNA) datasheet:
// FileType(1), FileOption(1), AccessRights(2), FileSize(3), [SDMOptions(1)], [SDMAccessRights(2)], [UIDOffset(3)], [SDMReadCtrOffset(3)],
// [PICCDataOffset(3)], [PICCDataOffset(3)], [SDMENCOffset(3)], [SDMENCLength(3)], [SDMMACOffset(3)], [SDMReadCtrLimit(3)]
// Note: arguments in brackets are optional; SW1 and SW2 are not included in backRespData
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetFileSettings(DNA_File file, byte* backRespData, byte* backRespLen)
{
  byte Cmd = 0xF5;
  byte sendData[15];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x09; // Lc
  sendData[5] = file; // FileNo
  DNA_CalculateCMACtNoData(Cmd, &sendData[5], 1, &sendData[6]);
  sendData[14] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (DNA_CheckResponseCMACtWithData(backData, backLen - 10, &backData[backLen - 10]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
  
  if(backLen < 17 || backLen > 44)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (*backRespLen < backLen - 10)
    return DNA_STATUS_NO_ROOM;
  
  memcpy(backRespData, backData, backLen - 10);
  *backRespLen = backLen - 10;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetFileSettings_AccessRights(DNA_File file, byte* backReadAccess, byte* backWriteAccess, byte* backReadWriteAccess, byte* backChangeAccess)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  byte backRespData[34];
  byte backRespLen = 34;
  dna_statusCode = DNA_Mac_GetFileSettings(file, backRespData, &backRespLen);
  
  if(dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  *backReadAccess = backRespData[3] >> 4;
  *backWriteAccess = backRespData[3] & 0b1111;
  *backReadWriteAccess = backRespData[2] >> 4;
  *backChangeAccess = backRespData[2] & 0b1111;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetFileSettings_CommMode(DNA_File file, DNA_CommMode* backCommMode)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  byte backRespData[34];
  byte backRespLen = 34;
  dna_statusCode = DNA_Mac_GetFileSettings(file, backRespData, &backRespLen);
  
  if(dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if((backRespData[1] & 0b11) == 0b10)
    *backCommMode = DNA_COMMMODE_PLAIN;
  else
    *backCommMode = DNA_CommMode(backRespData[1] & 0b11);
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetFileSettings_SDM(DNA_File file, bool* backSDMEnabled)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  byte backRespData[34];
  byte backRespLen = 34;
  dna_statusCode = DNA_Mac_GetFileSettings(file, backRespData, &backRespLen);
  
  if(dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  *backSDMEnabled = backRespData[1] & 0b01000000;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetKeyVersion(byte keyNumber, byte* backKeyVersion)
{
  byte Cmd = 0x64;
  byte sendData[15];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x09; // Lc
  sendData[5] = keyNumber; // KeyNo
  DNA_CalculateCMACtNoData(Cmd, &sendData[5], 1, &sendData[6]);
  sendData[14] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (DNA_CheckResponseCMACtWithData(backData, 1, &backData[1]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
  
  *backKeyVersion = backData[0];
  
  return DNA_STATUS_OK;
}


// Writes to backRespData 28 or 29 bytes according to tables 54, 56, 58 from NT4H2421Gx (NTAG 424 DNA) datasheet:
// VendorID, HWType, HWSubType, HWMajorVersion, HWMinorVersion, HWStorageSize, HWProtocol,
// VendorID, SWType, SWSubType, SWMajorVersion, SWMinorVersion, SWStorageSize, SWProtocol,
// UID(7), BatchNo(4), BatchNo/FabKey, FabKey/CWProd, YearProd, [FabKeyID]
// Note: arguments in brackets are optional; SW1 and SW2 are not included in backRespData
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetVersion(byte* backRespData, byte* backRespLen)
{
  byte backData[37];
  
  byte backLen;
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  
  dna_statusCode = DNA_Mac_GetVersion_native(0x60, 0xAF, backData, &backLen);
  
  if (dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if(backLen != 7)
    return DNA_WRONG_RESPONSE_LEN;
  
  
  // Mac mode can only be used on part 1 of GetVersion, but response mac is checked on all responses
  dna_statusCode = DNA_Plain_GetVersion_native(0xAF, 0xAF, &backData[7], &backLen);
  
  if (dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if(backLen != 7)
    return DNA_WRONG_RESPONSE_LEN;
  
  
  dna_statusCode = DNA_Plain_GetVersion_native(0xAF, 0x00, &backData[14], &backLen);
  
  if (dna_statusCode != DNA_STATUS_OK)
    return dna_statusCode;
  
  if(backLen != 22 && backLen != 23)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (DNA_CheckResponseCMACtWithData(backData, backLen + 6, &backData[backLen + 6]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
  
  if (*backRespLen < backLen + 6)
    return DNA_STATUS_NO_ROOM;
  
  memcpy(backRespData, backData, backLen + 6);
  *backRespLen = backLen + 6;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_ReadData(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  
  byte* finalBackData = new byte[length];
  uint16_t finalBackLen = 0;
  
  byte backLen = 51;
  if(length < 51)
    backLen = length;
  byte* backData = new byte[backLen];
  
  while (length > 51)
  {
    dna_statusCode = DNA_Mac_ReadData_native(file, 51, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    offset += 51;
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
    
    if (backLen < 51)
      length = 0;
    else
      length -= 51;
    backLen = 51;
  }
  
  if (length > 0)
  {
    dna_statusCode = DNA_Mac_ReadData_native(file, length, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
  }
  
  delete[] backData;
  
  if (*backReadLen < finalBackLen)
  {
    delete[] finalBackData;
    return DNA_STATUS_NO_ROOM;
  }
  
  memcpy(backReadData, finalBackData, finalBackLen);
  delete[] finalBackData;
  *backReadLen = finalBackLen;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_WriteData(DNA_File file, uint16_t length, byte offset, byte* sendData)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  uint16_t sendDataOffset = 0;
  
  while (length > 41)
  {
    dna_statusCode = DNA_Mac_WriteData_native(file, 41, offset, &sendData[sendDataOffset]);
    if (dna_statusCode != DNA_STATUS_OK)
      return dna_statusCode;
    
    offset += 41;
    sendDataOffset += 41;
    length -= 41;
  }
  
  if (length == 0)
    return DNA_STATUS_OK;
  
  return DNA_Mac_WriteData_native(file, length, offset, &sendData[sendDataOffset]);
}






/////////////////////////////////////////////////////////////////////////////////////
//
// Full communication mode (prior DNA_AuthenticateEV2 required)
//
/////////////////////////////////////////////////////////////////////////////////////


// Warning! "SDMEnabled = false" disables SDM for a file!
// Use this function if you do not need to use SDM (SDM is disabled by default on a new tag).
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_ChangeFileSettings(DNA_File file, DNA_CommMode commMode, byte readAccess, byte writeAccess, byte readWriteAccess, byte changeAccess, byte SDMEnabled)
{
  if(SDMEnabled)
    return DNA_SDM_NOT_IMPLEMENTED_IN_LIB;
  
  byte sendData[3];
  
  sendData[0] = commMode;
  sendData[1] = (readWriteAccess << 4) | changeAccess;
  sendData[2] = (readAccess << 4) | writeAccess;
  
  return DNA_Full_ChangeFileSettings(file, sendData, 3);
}


// sendData = FileOption, AccessRights(2), [SDMOptions], [SMDAccessRights(2)], [UIDOffset(3)], [SDMReadCtrOffset(3)],
// [PICCDataOffset(3)], [SDMMACInputOFFset(3)], [SDMENCOffset(3)], [SDMENCLength(3)], [SDMMACOffset(3)], [SDMReadCtrLimit(3)]
// Note: arguments in brackets are optional
// Use this function only if you want to use SDM and know what you are doing.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_ChangeFileSettings(DNA_File file, byte* sendData, byte sendDataLen)
{
  if(sendDataLen > 30)
    return DNA_STATUS_NO_ROOM;
  
  byte Cmd = 0x5F;
  byte lengthWithPadding = (sendDataLen & 0xF0) + 16;
  byte *sendData2 = new byte[lengthWithPadding + 15];
  
  sendData2[0] = 0x90; // CLA
  sendData2[1] = Cmd; // CMD
  sendData2[2] = 0x00; // P1
  sendData2[3] = 0x00; // P2
  sendData2[4] = lengthWithPadding + 9; // Lc
  sendData2[5] = file; // FileNo
  
  byte dataToEnc[32] = {};
  memcpy(dataToEnc, sendData, sendDataLen);
  dataToEnc[sendDataLen] = 0x80;
  
  DNA_CalculateDataEncAndCMACt(Cmd, dataToEnc, lengthWithPadding, &sendData2[5], 1, &sendData2[6]);
  
  sendData2[lengthWithPadding + 14] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, lengthWithPadding + 15, backData, &backLen);
  
  delete[] sendData2;
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if(backLen != 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_CheckResponseCMACt(backData);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_ChangeKey(byte keyNumber, byte* oldKey, byte* newKey, byte newKeyVersion)
{
  byte Cmd = 0xC4;
  
  byte sendData[47];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0; // P1
  sendData[3] = 0; // P2
  sendData[4] = 0x29; // LC - length of data (0x29 = 41)
  sendData[5] = keyNumber; // KeyNo
  
  byte keyData[32] = {};
  memcpy(keyData, newKey, 16);
  keyData[16] = newKeyVersion;
  
  if (keyNumber == 0)
  {
    keyData[17] = 0x80;
  }
  else
  {
    keyData[21] = 0x80;
    for (byte i = 0; i < 16; i++)
      keyData[i] = keyData[i] ^ oldKey[i];
    
    byte CRC32NK[4];
    DNA_CalculateCRC32NK(newKey, CRC32NK);
    memcpy(&keyData[17], CRC32NK, 4);
  }
  
  DNA_CalculateDataEncAndCMACt(Cmd, keyData, 32, &sendData[5], 1, &sendData[6]);
  
  sendData[46] = 0; // Le
  
  byte backData[61] = {};
  byte backLen = 61;
  
  StatusCode statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (keyNumber == 0)
  {
    if (backLen != 2)
      return DNA_WRONG_RESPONSE_LEN;
    return DNA_STATUS_OK;
  }
  
  if (backLen != 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_CheckResponseCMACt(backData);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_ChangeKey0(byte* newKey, byte newKeyVersion)
{
  return DNA_Full_ChangeKey(0, nullptr, newKey, newKeyVersion);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_GetCardUID(byte* backUID_7B)
{
  byte Cmd = 0x51;
  
  byte sendData[14];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x08; // Lc
  DNA_CalculateCMACtNoData(Cmd, nullptr, 0, &sendData[5]);
  sendData[13] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 26)
    return DNA_WRONG_RESPONSE_LEN;
  
  byte backDataDecrypted[16];
  
  byte IVResp[16];
  DNA_CalculateIVResp(IVResp);
  
  cbc.setKey(SesAuthEncKey, 16);
  cbc.setIV(IVResp, 16);
  cbc.decrypt(backDataDecrypted, backData, 16);
  
  if (DNA_CheckResponseCMACtWithData(backData, 16, &backData[16]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
    
  memcpy(backUID_7B, backDataDecrypted, 7);
  
  return DNA_STATUS_OK;
}


// Reads SDMReadCtr. This command works if you enable SDM on your own, but it is not implemented in this library currently.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_GetFileCounters(DNA_File file, uint32_t* backSDMReadCtr)
{
  byte Cmd = 0xF6;
  byte sendData[15];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 9; // Lc
  sendData[5] = file; // FileNo
  DNA_CalculateCMACtNoData(Cmd, &sendData[5], 1, &sendData[6]);
  sendData[14] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 26)
    return DNA_WRONG_RESPONSE_LEN;
  
  byte backDataDecrypted[16];
  
  byte IVResp[16];
  DNA_CalculateIVResp(IVResp);
  
  cbc.setKey(SesAuthEncKey, 16);
  cbc.setIV(IVResp, 16);
  cbc.decrypt(backDataDecrypted, backData, 16);
  
  if (DNA_CheckResponseCMACtWithData(backData, 16, &backData[16]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
  
  *backSDMReadCtr = backDataDecrypted[0] | backDataDecrypted[1] << 8 | backDataDecrypted[2] << 8;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_ReadData(DNA_File file, uint16_t length, byte offset, byte* backReadData, uint16_t* backReadLen)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  
  byte* finalBackData = new byte[length];
  uint16_t finalBackLen = 0;
  
  byte backLen = 47;
  if(length < 47)
    backLen = length;
  byte* backData = new byte[backLen];
  
  while (length > 47)
  {
    dna_statusCode = DNA_Full_ReadData_native(file, 47, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    offset += 47;
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
    
    if (backLen < 47)
      length = 0;
    else
      length -= 47;
    backLen = 47;
  }
  
  if (length > 0)
  {
    dna_statusCode = DNA_Full_ReadData_native(file, length, offset, backData, &backLen);
    if (dna_statusCode != DNA_STATUS_OK)
    {
      delete[] finalBackData;
      delete[] backData;
      return dna_statusCode;
    }
    
    memcpy(&finalBackData[finalBackLen], backData, backLen);
    finalBackLen += backLen;
  }
  
  delete[] backData;
  
  if (*backReadLen < finalBackLen)
  {
    delete[] finalBackData;
    return DNA_STATUS_NO_ROOM;
  }
  
  memcpy(backReadData, finalBackData, finalBackLen);
  delete[] finalBackData;
  *backReadLen = finalBackLen;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_SetConfiguration(byte* sendData, byte sendDataLen)
{
  byte Cmd = 0x5C;
  
  byte sendData2[31];
  
  sendData2[0] = 0x90; // CLA
  sendData2[1] = Cmd; // CMD
  sendData2[2] = 0x00; // P1
  sendData2[3] = 0x00; // P2
  sendData2[4] = 25; // Lc
  sendData2[5] = 0x0A; //Option
  
  byte dataToEnc[16] = {};
  memcpy(dataToEnc, sendData, sendDataLen);
  dataToEnc[sendDataLen] = 0x80;
  
  DNA_CalculateDataEncAndCMACt(Cmd, dataToEnc, 16, &sendData2[5], 1, &sendData2[6]);
  
  sendData2[30] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, sizeof(sendData2), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_CheckResponseCMACt(backData);
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_SetConfiguration_FailedCtrOption(bool FailedCtrEnabled, uint16_t TotFailCtrLimit, uint16_t TotFailCtrDecr)
{
  byte sendData[5] = {};
  if(FailedCtrEnabled)
    sendData[0] = 1;
  sendData[1] = TotFailCtrLimit & 0x00FF;
  sendData[2] = TotFailCtrLimit >> 8;
  sendData[3] = TotFailCtrDecr & 0x00FF;
  sendData[4] = TotFailCtrDecr >> 8;
  return DNA_Full_SetConfiguration(sendData, sizeof(sendData));
}


// Warning! Enables LRP (unsuported by this lib) permanently, when "turnLRPModeON_Permanent = true"! Use with care.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_SetConfiguration_PDCap2(bool turnLRPModeON_Permanent, byte PDCap2_5, byte PDCap2_6)
{
  byte sendData[10] = {};
  if(turnLRPModeON_Permanent)
    sendData[4] = 0b10;
  sendData[8] = PDCap2_5;
  sendData[9] = PDCap2_6;
  return DNA_Full_SetConfiguration(sendData, sizeof(sendData));
}


// Warning! Enables RandomID permanently! Use with care.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_SetConfiguration_Permanent_RandomID_ON()
{
  byte sendData = 0b10;
  return DNA_Full_SetConfiguration(&sendData, sizeof(sendData));
}


// Warning! Disables SDM chained writing permanently! Use with care.
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_SetConfiguration_Permanent_SDM_Chained_Write_OFF()
{
  byte sendData[2] = {};
  sendData[0] = 0b100;
  return DNA_Full_SetConfiguration(sendData, sizeof(sendData));
}


// Warning! It is strongly recommended not to disable StrongBackModulation!
MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_SetConfiguration_StrongBackModulation(bool StrongBackModulation)
{
  byte sendData = 0;
  if(StrongBackModulation)
    sendData = 1;
  return DNA_Full_SetConfiguration(&sendData, sizeof(sendData));
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_WriteData(DNA_File file, uint16_t length, byte offset, byte* sendData)
{
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  uint16_t sendDataOffset = 0;
  
  while (length > 31)
  {
    dna_statusCode = DNA_Full_WriteData_native(file, 31, offset, &sendData[sendDataOffset]);
    if (dna_statusCode != DNA_STATUS_OK)
      return dna_statusCode;
    
    offset += 31;
    sendDataOffset += 31;
    length -= 31;
  }
  
  if (length == 0)
    return DNA_STATUS_OK;
  
  return DNA_Full_WriteData_native(file, length, offset, &sendData[sendDataOffset]);
}






/////////////////////////////////////////////////////////////////////////////////////
//
// Helper functions
//
/////////////////////////////////////////////////////////////////////////////////////


// PICC_DeselectAndWakeupA is a modified verison of PICC_IsNewCardPresent from MFRC522Extended.cpp in MFRC522 lib.
// TCL_Deselect was added and PICC_RequestA was changed to PICC_WakeupA
// Deselects current card and returns true if any card responds to a WakeupA command.
bool MFRC522_NTAG424DNA::PICC_TryDeselectAndWakeupA() {
  byte bufferATQA[2];
  byte bufferSize = sizeof(bufferATQA);
  
  TCL_Deselect(&tag); // deselect current card

  // Reset baud rates
  PCD_WriteRegister(TxModeReg, 0x00);
  PCD_WriteRegister(RxModeReg, 0x00);
  // Reset ModWidthReg
  PCD_WriteRegister(ModWidthReg, 0x26);

  MFRC522::StatusCode result = PICC_WakeupA(bufferATQA, &bufferSize);

  if (result == STATUS_OK || result == STATUS_COLLISION) {
    tag.atqa = ((uint16_t)bufferATQA[1] << 8) | bufferATQA[0];
    tag.ats.size = 0;
    tag.ats.fsc = 32;  // default FSC value

    // Defaults for TA1
    tag.ats.ta1.transmitted = false;
    tag.ats.ta1.sameD = false;
    tag.ats.ta1.ds = MFRC522Extended::BITRATE_106KBITS;
    tag.ats.ta1.dr = MFRC522Extended::BITRATE_106KBITS;

    // Defaults for TB1
    tag.ats.tb1.transmitted = false;
    tag.ats.tb1.fwi = 0;  // TODO: Don't know the default for this!
    tag.ats.tb1.sfgi = 0;  // The default value of SFGI is 0 (meaning that the card does not need any particular SFGT)

    // Defaults for TC1
    tag.ats.tc1.transmitted = false;
    tag.ats.tc1.supportsCID = true;
    tag.ats.tc1.supportsNAD = false;

    memset(tag.ats.data, 0, FIFO_SIZE - 2);

    tag.blockNumber = false;
    return true;
  }
  return false;
}






/////////////////////////////////////////////////////////////////////////////////////
//
// Protected functions
//
/////////////////////////////////////////////////////////////////////////////////////


MFRC522Extended::StatusCode MFRC522_NTAG424DNA::DNA_AuthenticateEV2First_Part1(byte keyNumber, byte* backData, byte* backLen)
{
  byte sendData[8];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = 0x71; // CMD
  sendData[2] = 0; // P1
  sendData[3] = 0; // P2
  sendData[4] = 0x02; // Lc - not mentioned in the documentation, but it is the length of KeyNo + LenCap + PCDcap2
  sendData[5] = keyNumber; // KeyNo
  sendData[6] = 0; // LenCap, 0 = no PCDcap2
  sendData[7] = 0; // Le
  
  return DNA_BasicTransceive(sendData, sizeof(sendData), backData, backLen);
}


MFRC522Extended::StatusCode MFRC522_NTAG424DNA::DNA_AuthenticateEV2First_Part2(byte* inData, byte* backData, byte* backLen)
{
  byte sendData[38];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = 0xAF; // CMD
  sendData[2] = 0; // P1
  sendData[3] = 0; // P2
  sendData[4] = 0x20; // LC
  memcpy(&sendData[5], inData, 32);
  sendData[37] = 0; // Le
  
  return DNA_BasicTransceive(sendData, sizeof(sendData), backData, backLen);
}


MFRC522Extended::StatusCode MFRC522_NTAG424DNA::DNA_AuthenticateEV2NonFirst_Part1(byte keyNumber, byte* backData, byte* backLen)
{
  byte sendData[7];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = 0x77; // CMD
  sendData[2] = 0; // P1
  sendData[3] = 0; // P2
  sendData[4] = 0x01; // Lc
  sendData[5] = keyNumber; // KeyNo
  sendData[6] = 0; // Le
  
  return DNA_BasicTransceive(sendData, sizeof(sendData), backData, backLen);
}


MFRC522Extended::StatusCode MFRC522_NTAG424DNA::DNA_AuthenticateEV2NonFirst_Part2(byte* inData, byte* backData, byte* backLen)
{
  return DNA_AuthenticateEV2First_Part2(inData, backData, backLen);
}






MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_GetVersion_native(byte Cmd, byte expectedSV2, byte* backRespData, byte* backRespLen)
{
  byte sendData[5];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != expectedSV2)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if(backLen != 9 && backLen != 16 && backLen != 17 && backLen != 24 && backLen != 25)
    return DNA_WRONG_RESPONSE_LEN;
  
  memcpy(backRespData, backData, backLen - 2);
  *backRespLen = backLen - 2;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOReadBinary_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen)
{
  if (length > 59)
    return DNA_STATUS_NO_ROOM;
  
  byte sendData[5];
  
  sendData[0] = 0; // CLA
  sendData[1] = 0xB0; // CMD
  sendData[2] = 0x82 + file; // P1
  sendData[3] = offset; // P2 (offset)
  // MFRC522 can read max 0x3B = 59 bytes from a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are contained in FIFO - received from PICC)
  // 59 (file contents) + 1 (SW1) + 1 (SW2)      + 1 (pcb) + 2 (crc) = 64 (FIFO size)
  sendData[4] = length; // Le = bytes to read from the file
  
  byte backData[61] = {};
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x90 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen < 2 || backLen > length + 2)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (backLen > 2)
    memcpy(backReadData, backData, backLen - 2);
  *backReadLen = backLen - 2;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ISOUpdateBinary_native(DNA_File file, byte length, byte offset, byte* sendData)
{
  if (length > 58)
    return DNA_STATUS_NO_ROOM;
  
  byte* sendData2 = new byte[length + 5];
  
  sendData2[0] = 0; // CLA
  sendData2[1] = 0xD6; // CMD
  sendData2[2] = 0x82 + file; // P1
  sendData2[3] = offset; // P2 (offset)
  // MFRC522 can write max 0x3A = 58 bytes to a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are not in FIFO, but in a different register for sending)
  // 58 (file contents) + 1 (pcb) + 5 (CLA, CMD, P1, P2, Lc) = 64 (FIFO size)
  sendData2[4] = length; // Lc
  memcpy(&sendData2[5], sendData, length);
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, length + 5, backData, &backLen);
  
  delete[] sendData2;
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x90 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 2)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_ReadData_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen)
{
  if (length > 59)
    return DNA_STATUS_NO_ROOM;
  
  byte sendData[13];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = 0xAD; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x07; // LC
  sendData[5] = file; // FileNo
  sendData[6] = offset; // Offset
  sendData[7] = 0x00; // (Offset)
  sendData[8] = 0x00; // (Offset)
  sendData[9] = length; // Length
  sendData[10] = 0x00; // (Length)
  sendData[11] = 0x00; // (Length)
  sendData[12] = 0x00; // Le
  
  // MFRC522 can read max 0x3B = 59 bytes from a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are contained in FIFO - received from PICC)
  // 59 (file contents) + 1 (SW1) + 1 (SW2)      + 1 (pcb) + 2 (crc) = 64 (FIFO size)
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen > length + 2)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (backLen > 2)
    memcpy(backReadData, backData, backLen - 2);
  *backReadLen = backLen - 2;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Plain_WriteData_native(DNA_File file, byte length, byte offset, byte* sendData)
{
  if (length > 50)
    return DNA_STATUS_NO_ROOM;
  
  byte* sendData2 = new byte[length + 13];
  
  sendData2[0] = 0x90; // CLA
  sendData2[1] = 0x8D; // CMD
  sendData2[2] = 0x00; // P1
  sendData2[3] = 0x00; // P2
  sendData2[4] = 7 + length; // Lc
  sendData2[5] = file; // FileNo
  sendData2[6] = offset; // Offset
  sendData2[7] = 0x00; // (Offset)
  sendData2[8] = 0x00; // (Offset)
  // MFRC522 can write max 0x32 = 50 bytes to a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are not in FIFO, but in a different register for sending)
  // 50 (file contents) + 1 (pcb) + 13 (CLA, CMD, P1, P2, Lc, FileNo, Offset-3, Length-3, Le) = 64 (FIFO size)
  sendData2[9] = length; // Length
  sendData2[10] = 0x00; // (Length)
  sendData2[11] = 0x00; // (Length)
  memcpy(&sendData2[12], sendData, length);
  sendData2[length + 12] = 0x00; // Le
  
  byte backData[64];
  byte backLen = 64;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, length + 13, backData, &backLen);
  
  delete[] sendData2;
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 2)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_STATUS_OK;
}






MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_GetVersion_native(byte Cmd, byte expectedSV2, byte* backRespData, byte* backRespLen)
{
  byte sendData[14];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x08; // Lc
  DNA_CalculateCMACtNoData(Cmd, nullptr, 0, &sendData[5]);
  sendData[13] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != expectedSV2)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if(backLen != 9)
    return DNA_WRONG_RESPONSE_LEN;
  
  memcpy(backRespData, backData, backLen - 2);
  *backRespLen = backLen - 2;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_ReadData_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen)
{
  if (length > 51)
    return DNA_STATUS_NO_ROOM;
  
  byte Cmd = 0xAD;
  byte sendData[21];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x0F; // Lc
  sendData[5] = file; // FileNo
  sendData[6] = offset; // Offset
  sendData[7] = 0x00; // (Offset)
  sendData[8] = 0x00; // (Offset)
  // MFRC522 can read max 0x3B = 59 bytes from a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are contained in FIFO - received from PICC)
  // 59 (file contents) + 1 (SW1) + 1 (SW2)      + 1 (pcb) + 2 (crc) = 64 (FIFO size)
  sendData[9] = length; // Length
  sendData[10] = 0x00; // (Length)
  sendData[11] = 0x00; // (Length)
  DNA_CalculateCMACtNoData(Cmd, &sendData[5], 7, &sendData[12]);
  sendData[20] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != length + 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  if (DNA_CheckResponseCMACtWithData(backData, length, &backData[length]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
  
  if (*backReadLen < length)
    return DNA_STATUS_NO_ROOM;
    
  if (backLen > 10)
    memcpy(backReadData, backData, length);
  *backReadLen = length;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Mac_WriteData_native(DNA_File file, byte length, byte offset, byte* sendData)
{
  if (length > 41)
    return DNA_STATUS_NO_ROOM;
  
  byte Cmd = 0x8D;
  
  byte* sendData2 = new byte[length + 21];
  
  sendData2[0] = 0x90; // CLA
  sendData2[1] = Cmd; // CMD
  sendData2[2] = 0x00; // P1
  sendData2[3] = 0x00; // P2
  sendData2[4] = 7 + length + 8; // Lc
  sendData2[5] = file; // FileNo
  sendData2[6] = offset; // Offset
  sendData2[7] = 0x00; // (Offset)
  sendData2[8] = 0x00; // (Offset)
  // MFRC522 can write max 0x32 = 50 bytes to a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are not in FIFO, but in a different register for sending)
  // 50 (file contents) + 1 (pcb) + 13 (CLA, CMD, P1, P2, Lc, FileNo, Offset-3, Length-3, Le) = 64 (FIFO size)
  sendData2[9] = length; // Length
  sendData2[10] = 0x00; // (Length)
  sendData2[11] = 0x00; // (Length)
  memcpy(&sendData2[12], sendData, length);
  DNA_CalculateCMACtNoData(Cmd, &sendData2[5], 7 + length, &sendData2[12 + length]);
  sendData2[length + 20] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, length + 21, backData, &backLen);
  
  delete[] sendData2;
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_CheckResponseCMACt(backData);
}






MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_ReadData_native(DNA_File file, byte length, byte offset, byte* backReadData, byte* backReadLen)
{
  if (length > 47)
    return DNA_STATUS_NO_ROOM;
  
  byte Cmd = 0xAD;
  byte sendData[21];
  
  sendData[0] = 0x90; // CLA
  sendData[1] = Cmd; // CMD
  sendData[2] = 0x00; // P1
  sendData[3] = 0x00; // P2
  sendData[4] = 0x0F; // Lc
  sendData[5] = file; // FileNo
  sendData[6] = offset; // Offset
  sendData[7] = 0x00; // (Offset)
  sendData[8] = 0x00; // (Offset)
  // MFRC522 can read max 0x3B = 59 bytes from a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are contained in FIFO - received from PICC)
  // 59 (file contents) + 1 (SW1) + 1 (SW2)      + 1 (pcb) + 2 (crc) = 64 (FIFO size)
  sendData[9] = length; // Length
  sendData[10] = 0x00; // (Length)
  sendData[11] = 0x00; // (Length)
  DNA_CalculateCMACtNoData(Cmd, &sendData[5], 7, &sendData[12]);
  sendData[20] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData, sizeof(sendData), backData, &backLen);
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  byte lengthWithPadding = (length & 0xF0) + 16;
  
  if (backLen != lengthWithPadding + 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  
  byte backDataDecrypted[48];
  
  byte IVResp[16];
  DNA_CalculateIVResp(IVResp);
  
  cbc.setKey(SesAuthEncKey, 16);
  cbc.setIV(IVResp, 16);
  cbc.decrypt(backDataDecrypted, backData, lengthWithPadding);
  
  if (DNA_CheckResponseCMACtWithData(backData, lengthWithPadding, &backData[lengthWithPadding]) == DNA_WRONG_RESPONSE_CMAC)
    return DNA_WRONG_RESPONSE_CMAC;
  
  if (*backReadLen < length)
    return DNA_STATUS_NO_ROOM;
    
  if (backLen > 10)
    memcpy(backReadData, backDataDecrypted, length);
  *backReadLen = length;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_Full_WriteData_native(DNA_File file, byte length, byte offset, byte* sendData)
{
  if (length > 31)
    return DNA_STATUS_NO_ROOM;
  
  byte Cmd = 0x8D;
  byte lengthWithPadding = (length & 0xF0) + 16;
  byte* sendData2 = new byte[lengthWithPadding + 21];
  
  sendData2[0] = 0x90; // CLA
  sendData2[1] = Cmd; // CMD
  sendData2[2] = 0x00; // P1
  sendData2[3] = 0x00; // P2
  sendData2[4] = lengthWithPadding + 15; // Lc
  sendData2[5] = file; // FileNo
  sendData2[6] = offset; // Offset
  sendData2[7] = 0x00; // (Offset)
  sendData2[8] = 0x00; // (Offset)
  // MFRC522 can write max 0x32 = 50 bytes to a file at a time
  // its FIFO buffer has only 64 bytes (2 CRC bytes are not in FIFO, but in a different register for sending)
  // 50 (file contents) + 1 (pcb) + 13 (CLA, CMD, P1, P2, Lc, FileNo, Offset-3, Length-3, Le) = 64 (FIFO size)
  sendData2[9] = length; // Length
  sendData2[10] = 0x00; // (Length)
  sendData2[11] = 0x00; // (Length)
  
  byte dataToEnc[48] = {};
  memcpy(dataToEnc, sendData, length);
  dataToEnc[length] = 0x80;
  
  DNA_CalculateDataEncAndCMACt(Cmd, dataToEnc, lengthWithPadding, &sendData2[5], 7, &sendData2[12]);
  
  sendData2[lengthWithPadding + 20] = 0x00; // Le
  
  byte backData[61];
  byte backLen = 61;
  
  MFRC522Extended::StatusCode statusCode;
  statusCode = DNA_BasicTransceive(sendData2, lengthWithPadding + 21, backData, &backLen);
  
  delete[] sendData2;
  
  if (statusCode != STATUS_OK)
    return (DNA_StatusCode) statusCode;
  
  if (!DNA_IncrementCmdCtr())
    return DNA_CMD_CTR_OVERFLOW;
  
  if (backData[backLen - 2] != 0x91 || backData[backLen - 1] != 0x00)
    return DNA_InterpretErrorCode(&backData[backLen - 2]);
  
  if (backLen != 10)
    return DNA_WRONG_RESPONSE_LEN;
  
  return DNA_CheckResponseCMACt(backData);
}






MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_CheckResponseCMACt(byte* responseCMACt)
{
  byte respData[7] = {0};
  respData[1] = CmdCtr[0];
  respData[2] = CmdCtr[1];
  memcpy(&respData[3], TI, 4);
  
  byte CMACtResp[8];
  DNA_CalculateCMACt(respData, 7, CMACtResp);
  
  for (byte i = 0; i < 8; i++)
    if (responseCMACt[i] != CMACtResp[i])
      return DNA_WRONG_RESPONSE_CMAC;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_CheckResponseCMACtWithData(byte* data, byte dataLen, byte* responseCMACt)
{
  byte* respData = new byte[dataLen + 7];
  respData[0] = 0;
  respData[1] = CmdCtr[0];
  respData[2] = CmdCtr[1];
  memcpy(&respData[3], TI, 4);
  memcpy(&respData[7], data, dataLen);
  
  byte CMACtResp[8];
  DNA_CalculateCMACt(respData, dataLen + 7, CMACtResp);
  delete[] respData;
  
  for (byte i = 0; i < 8; i++)
    if (responseCMACt[i] != CMACtResp[i])
      return DNA_WRONG_RESPONSE_CMAC;
  
  return DNA_STATUS_OK;
}


MFRC522_NTAG424DNA::DNA_StatusCode MFRC522_NTAG424DNA::DNA_InterpretErrorCode(byte* SW1_2)
{
  uint16_t SW = SW1_2[0] << 8 | SW1_2[1];
  switch(SW)
  {
    case 0x6581:
      return MFRC522_NTAG424DNA::MEMORY_ERROR;
    case 0x6700:
      return MFRC522_NTAG424DNA::LENGTH_ERROR;
    case 0x6982:
      return MFRC522_NTAG424DNA::SECURITY_NOT_SATISFIED;
    case 0x6985:
      return MFRC522_NTAG424DNA::CONDITIONS_NOT_SATISFIED;
    case 0x6A82:
      return MFRC522_NTAG424DNA::FILE_OR_APP_NOT_FOUND;
    case 0x6A86:
      return MFRC522_NTAG424DNA::INCORRECT_PARAMS;
    case 0x6A87:
      return MFRC522_NTAG424DNA::INCORRECT_LC;
    case 0x6A00:
      return MFRC522_NTAG424DNA::CLA_NOT_SUPPORTED;
    case 0x910B:
      return MFRC522_NTAG424DNA::COMMAND_NOT_FOUND;
    case 0x910C:
      return MFRC522_NTAG424DNA::COMMAND_FORMAT_ERROR;
    case 0x911C:
      return MFRC522_NTAG424DNA::ILLEGAL_COMMAND_CODE;
    case 0x911E:
      return MFRC522_NTAG424DNA::INTEGRITY_ERROR;
    case 0x9140:
      return MFRC522_NTAG424DNA::NO_SUCH_KEY;
    case 0x917E:
      return MFRC522_NTAG424DNA::LENGTH_ERROR;
    case 0x919D:
      return MFRC522_NTAG424DNA::PERMISSION_DENIED;
    case 0x919E:
      return MFRC522_NTAG424DNA::PARAMETER_ERROR;
    case 0x91AD:
      return MFRC522_NTAG424DNA::AUTHENTICATION_DELAY;
    case 0x91AE:
      return MFRC522_NTAG424DNA::AUTHENTICATION_ERROR;
    case 0x91AF:
      return MFRC522_NTAG424DNA::ADDITIONAL_FRAME;
    case 0x91BE:
      return MFRC522_NTAG424DNA::BOUNDARY_ERROR;
    case 0x91CA:
      return MFRC522_NTAG424DNA::COMMAND_ABORTED;
    case 0x91EE:
      return MFRC522_NTAG424DNA::MEMORY_ERROR;
    case 0x91F0:
      return MFRC522_NTAG424DNA::FILE_NOT_FOUND;
    default:
      return MFRC522_NTAG424DNA::DNA_UNKNOWN_ERROR;
  }
}


bool MFRC522_NTAG424DNA::DNA_IncrementCmdCtr()
{
  if(CmdCtr[0] == 0xFF)
  {
    if(CmdCtr[1] == 0xFF)
      return false;
    CmdCtr[0] = 0;
    CmdCtr[1] += 1;
  }
  else
  {
    CmdCtr[0] += 1;
  }
  return true;
}


void MFRC522_NTAG424DNA::DNA_CalculateCMACt(byte* CMACInput, byte CMACInputSize, byte* backCMACt)
{
  byte CMAC[16];
  cmac.generateMAC(CMAC, SesAuthMacKey, CMACInput, CMACInputSize);
  
  byte CMACt[8];
  for (byte i = 0; i < 8; i++)
    CMACt[i] = CMAC[i * 2 + 1];
  memcpy(backCMACt, CMACt, 8);
}


void MFRC522_NTAG424DNA::DNA_CalculateCMACtNoData(byte Cmd, byte* CmdHeader, byte CmdHeaderLen, byte* backCMACt)
{
  byte* CMACinput = new byte[CmdHeaderLen + 7]; // Cmd CmdCtr[2] TI[4] CmdHeader[]
  CMACinput[0] = Cmd; // Cmd
  CMACinput[1] = CmdCtr[0];
  CMACinput[2] = CmdCtr[1];
  memcpy(&CMACinput[3], TI, 4);
  memcpy(&CMACinput[7], CmdHeader, CmdHeaderLen);
  
  byte CMACt[8];
  DNA_CalculateCMACt(CMACinput, CmdHeaderLen + 7, CMACt);
  delete[] CMACinput;
  
  memcpy(backCMACt, CMACt, 8);
}


void MFRC522_NTAG424DNA::DNA_CalculateCRC32NK(byte* message16, byte* backCRC)
{
  uint32_t crc;
  crc = CRC32::calculate(message16, 16) & 0xFFFFFFFF ^ 0xFFFFFFFF;
  memcpy(backCRC, &crc, 4);
}


void MFRC522_NTAG424DNA::DNA_CalculateDataEncAndCMACt(byte Cmd, byte* dataToEnc, byte dataToEncLen, byte* CmdHeader, byte CmdHeaderLen, byte* backDataEncAndCMACt)
{
  byte* dataEnc = new byte[dataToEncLen];
  
  byte IVCmd[16];
  
  DNA_CalculateIVCmd(IVCmd);
  
  cbc.setKey(SesAuthEncKey, 16);
  cbc.setIV(IVCmd, 16);
  cbc.encrypt(dataEnc, dataToEnc, dataToEncLen);
  
  memcpy(backDataEncAndCMACt, dataEnc, dataToEncLen);
  
  byte* CMACinput = new byte[CmdHeaderLen + dataToEncLen + 7]; // Cmd CmdCtr[2] TI[4] CmdHeader[] dataToEnc[]
  CMACinput[0] = Cmd; // Cmd
  CMACinput[1] = CmdCtr[0];
  CMACinput[2] = CmdCtr[1];
  memcpy(&CMACinput[3], TI, 4);
  memcpy(&CMACinput[7], CmdHeader, CmdHeaderLen);
  memcpy(&CMACinput[7 + CmdHeaderLen], dataEnc, dataToEncLen);
  delete[] dataEnc;
  
  byte CMACt[8];
  DNA_CalculateCMACt(CMACinput, CmdHeaderLen + dataToEncLen + 7, CMACt);
  delete[] CMACinput;
  
  memcpy(&backDataEncAndCMACt[dataToEncLen], CMACt, 8);
}


void MFRC522_NTAG424DNA::DNA_CalculateIV(byte b0, byte b1, byte* backIV)
{
  // b0 b1 TI 00000000000000000000
  byte IV[16] = {b0, b1};
  for (byte i = 0; i < 4; i++)
    IV[i + 2] = TI[i];
  IV[6] = CmdCtr[0];
  IV[7] = CmdCtr[1];
  
  byte zeroIV[16] = {}; // 00000000000000000000000000000000
  byte IVEnc[16];
  cbc.setKey(SesAuthEncKey, 16);
  cbc.setIV(zeroIV, 16);
  cbc.encrypt(IVEnc, IV, 16);
  
  memcpy(backIV, IVEnc, 16);
}


void MFRC522_NTAG424DNA::DNA_CalculateIVCmd(byte* backIVCmd)
{
  DNA_CalculateIV(0xA5, 0x5A, backIVCmd);
}


void MFRC522_NTAG424DNA::DNA_CalculateIVResp(byte* backIVResp)
{
  DNA_CalculateIV(0x5A, 0xA5, backIVResp);
}


void MFRC522_NTAG424DNA::DNA_GenerateSesAuthKeys(byte* authKey, byte* RndA, byte* RndB)
{
  byte SV[32];
  
  DNA_CalculateSV1(RndA, RndB, SV);
  cmac.generateMAC(SesAuthEncKey, authKey, SV, 32);
  
  DNA_CalculateSV2(RndA, RndB, SV);
  cmac.generateMAC(SesAuthMacKey, authKey, SV, 32);
}


void MFRC522_NTAG424DNA::DNA_CalculateSV(byte b0, byte b1, byte* RndA, byte* RndB, byte* backSV)
{
  // b0 b1 00010080 RndA[15..14] RndA[13..8]^RndB[15..10] RndB[9..0] RndA[7..0]
  byte SV[32] = {b0, b1, 0x00, 0x01, 0x00, 0x80, RndA[0], RndA[1]};
  for (byte i = 0; i < 16; i++)
    SV[i + 8] = RndB[i];
  for (byte i = 0; i < 8; i++)
    SV[i + 24] = RndA[i + 8];
  for (byte i = 0; i < 6; i++)
    SV[8 + i] ^= RndA[i + 2];
  memcpy(backSV, SV, 32);
}


void MFRC522_NTAG424DNA::DNA_CalculateSV1(byte* RndA, byte* RndB, byte* backSV1)
{
  DNA_CalculateSV(0xA5, 0x5A, RndA, RndB, backSV1);
}


void MFRC522_NTAG424DNA::DNA_CalculateSV2(byte* RndA, byte* RndB, byte* backSV2)
{
  DNA_CalculateSV(0x5A, 0xA5, RndA, RndB, backSV2);
}
