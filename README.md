

# MFRC522_NTAG424DNA

Arduino RFID/NFC Library for NXP NTAG 424 DNA tags using MFRC522.

Read and write a NTAG 424 DNA card or tag. Plain, Mac and Full communication modes supported. LRP and SDM not yet supported.

**Warning! This library and its dependencies take a lot of flash and SRAM.** Basic programs should work on Arduino Uno, but even some medium-complexity ones might be unstable. It is recommended to use ESP8266 instead. This library should work on NodeMCU as well, but it was not tested.

To use this library you have to install two libraries manually (see **Dependencies** section).

Author: Piotr Obst

## DNA_StatusCode numbers
- DNA_STATUS_OK = 0, // Success (and 0x9000, 0x9100 - OPERATION_OK / Successful operaton)
- DNA_STATUS_ERROR = 1, // Error in communication
- DNA_STATUS_COLLISION = 2, // Collission detected
- DNA_STATUS_TIMEOUT = 3, // Timeout in communication.
- DNA_STATUS_NO_ROOM = 4, // A buffer is not big enough.
- DNA_STATUS_INTERNAL_ERROR = 5, // Internal error in the code. Should not happen ;-)
- DNA_STATUS_INVALID = 6, // Invalid argument.
- DNA_STATUS_CRC_WRONG = 7, // The CRC_A does not match
- COMMAND_NOT_FOUND = 8, // (910B) - Status used only in Read_Sig.
- COMMAND_FORMAT_ERROR = 9, // (910C) - Status used only in Read_Sig.
- ILLEGAL_COMMAND_CODE = 10, // (911C) Command code not supported.
- INTEGRITY_ERROR = 11, // (911E) CRC or MAC does not match data. Padding bytes not valid.
- NO_SUCH_KEY = 12, // (9140) Invalid key number specified.
- LENGTH_ERROR = 13, // (6700, 917E) Length of command string invalid.
- PERMISSION_DENIED = 14, // (919D) Current configuration / status does not allow the requested command.
- PARAMETER_ERROR = 15, // (919E) Value of the parameter(s) invalid.
- AUTHENTICATION_DELAY = 16, // (91AD) Currently not allowed to authenticate. Keep trying until full delay is spent.
- AUTHENTICATION_ERROR = 17, // (91AE) Current authentication status does not allow the requested command.
- ADDITIONAL_FRAME = 18, // (91AF) Additionaldata frame is expected to be sent.
- BOUNDARY_ERROR = 19, // (91BE) Attempt to read/write data from/to beyond the file's/record's limits. Attempt to exceed the limits of a value file.
- COMMAND_ABORTED = 20, // (91CA) Previous Command was not fully completed. Not all Frames were requested or provided by the PCD.
- MEMORY_ERROR = 21, // (6581, 91EE) Failure when reading or writing to non-volatile memory.
- FILE_NOT_FOUND = 22, // (91F0) Specified file number does not exist.
- SECURITY_NOT_SATISFIED = 23, // (6982) Security status not satisfied.
- CONDITIONS_NOT_SATISFIED = 24, // (6985) Conditions of use not satisfied.
- FILE_OR_APP_NOT_FOUND = 25, // (6A82) File or application not found.
- INCORRECT_PARAMS = 26, // (6A86) Incorrect parameters P1-P2.
- INCORRECT_LC = 27, // (6A87) Lc inconsistent with parameters P1-P2.
- CLA_NOT_SUPPORTED = 28, // (6E00) CLA not supported
- DNA_WRONG_RESPONSE_LEN = 29,
- DNA_WRONG_RESPONSE_CMAC = 30,
- DNA_WRONG_RNDA = 31,
- DNA_CMD_CTR_OVERFLOW = 32,
- DNA_UNKNOWN_ERROR = 33,
- DNA_SDM_NOT_IMPLEMENTED_IN_LIB = 34,
- DNA_STATUS_MIFARE_NACK = 0xff // A MIFARE PICC responded with NAK.

## What works and not?

### Works
- DNA_AuthenticateEV2First
- DNA_AuthenticateEV2NonFirst
- DNA_Plain_GetFileSettings
- DNA_Plain_GetFileSettings_AccessRights
- DNA_Plain_GetFileSettings_CommMode
- DNA_Plain_GetFileSettings_SDM
- DNA_Plain_GetVersion
- DNA_Plain_ISOReadBinary
- DNA_Plain_ISOSelectFile
- DNA_Plain_ISOSelectFile_Application
- DNA_Plain_ISOSelectFile_PICC
- DNA_Plain_ISOUpdateBinary
- DNA_Plain_ReadData
- DNA_Plain_WriteData
- DNA_Mac_GetFileSettings
- DNA_Mac_GetFileSettings_AccessRights
- DNA_Mac_GetFileSettings_CommMode
- DNA_Mac_GetFileSettings_SDM
- DNA_Mac_GetKeyVersion
- DNA_Mac_GetVersion
- DNA_Mac_ReadData
- DNA_Mac_WriteData
- DNA_Full_ChangeKey
- DNA_Full_ChangeKey0
- DNA_Full_GetCardUID
- DNA_Full_ReadData
- DNA_Full_SetConfiguration
- DNA_Full_SetConfiguration_FailedCtrOption
- DNA_Full_SetConfiguration_Permanent_RandomID_ON
- DNA_Full_SetConfiguration_Permanent_SDM_Chained_Write_OFF
- DNA_Full_SetConfiguration_StrongBackModulation
- DNA_Full_WriteData

### Works partially
- DNA_Plain_ChangeFileSettings - works only if SDM is disabled.
- DNA_Plain_Read_Sig - reads signature, but does not verify it due to license terms (see https://www.nxp.com/confidential/AN11350 and https://community.nxp.com/t5/NFC-Knowledge-Base/Demo-for-Originality-Signature-Verification/ta-p/1278669). You can verify the signature on your own.
- DNA_Full_ChangeFileSettings - works only if SDM is disabled.
- DNA_Full_GetFileCounters - works if SDM is enabled, but SDM is not implemented.
- DNA_Full_SetConfiguration_PDCap2 - sets PDCap2.5 and PDCap2.6, can turn LRP on permanently, but LRP is not implemented (use with care).

### Does not work
- DNA_Full_Read_Sig - MFRC522 hardware buffer is only 64 B long, which is not enough for this command.

## Compatible boards
Tested on **Arduino Uno** and **ESP8266** (on **ESP-12E**, **ESP-12F**, **ESP-12S** modules).
Not tested on **ESP-12** (without a letter) and other **ESP** modules.

## Pin layout / how to connect?
See https://github.com/miguelbalboa/rfid#pin-layout

## Dependencies
- **MFRC522** by GithubCommunity
	- from: Arduino Library Manager (installed automatically)
- **CryptoAES_CBC** by Piotr Obst, Rhys Weatherley
	- from: Arduino Library Manager (installed automatically)
- **CRC32** by Christopher Baker
	- from: Arduino Library Manager (installed automatically)
- **AES_CMAC** by Piotr Obst, Industrial Shields (Boot&Work Corp, S.L.)
	- from: Arduino Library Manager (installed automatically)

## License

MIT License

Copyright (c) 2023 Piotr Obst

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
