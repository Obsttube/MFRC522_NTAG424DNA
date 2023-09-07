/*
 * Typical pin layout used:
 * ------------------------------------------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino   Arduino          Arduino     NodeMCU
 *             Reader/PCD   Uno/101       Mega      Nano v3   Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin       Pin              Pin         Pin
 * ------------------------------------------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9        RESET/ICSP-5     RST         D1 / GPIO5 (#define RST_PIN 5)
 * SPI SS      SDA(SS)      10            53        D10       10               10          D2 / GPIO4 (#define SS_PIN 4)
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11       ICSP-4           16          D7 / GPIO13
 * SPI MISO    MISO         12 / ICSP-1   50        D12       ICSP-1           14          D6 / GPIO12
 * SPI SCK     SCK          13 / ICSP-3   52        D13       ICSP-3           15          D5 / GPIO14
 *
 * More pin layouts for other boards can be found here: https://github.com/miguelbalboa/rfid#pin-layout
 */

#include <MFRC522_NTAG424DNA.h>

#define SS_PIN 10 // change to 4 for NodeMCU
#define RST_PIN 9 // change to 5 for NodeMCU

MFRC522_NTAG424DNA ntag(SS_PIN, RST_PIN);
bool deselectAndWakeupA = false;

void setup() { 
  Serial.begin(9600);
  SPI.begin();
  ntag.PCD_Init();
  
  // if analog input pin 0 is unconnected, random analog
  // noise will cause the call to randomSeed() to generate
  // different seed numbers each time the sketch runs.
  // randomSeed() will then shuffle the random function.
  randomSeed(analogRead(0));
  
  // wait one second for the Serial to connect (recommended on NodeMCU / ESP8266, can be removed on Arduino Uno)
  delay(1000);
  Serial.println(F("POWER ON"));
}

void loop() {
  
  // Errors other than timeout appear often when slowly approaching a card to the reader.
  // When it happens, the card has to be deselected and woken up.
  if (deselectAndWakeupA){
    deselectAndWakeupA = false;
    if (!ntag.PICC_TryDeselectAndWakeupA())
      return;
  }else if (!ntag.PICC_IsNewCardPresent()){
      return;
  }
  
  if(!ntag.PICC_ReadCardSerial())
    return;
  
  MFRC522_NTAG424DNA::DNA_StatusCode dna_statusCode;
  dna_statusCode = ntag.DNA_Plain_ISOSelectFile_Application();
  if (dna_statusCode != MFRC522_NTAG424DNA::DNA_STATUS_OK){
    Serial.print(F("Plain_ISOSelectFile STATUS NOT OK: "));
    // For a list of status codes corresponding to these numbers, refer to https://github.com/obsttube/mfrc522_ntag424dna
    Serial.println(dna_statusCode);
    if (dna_statusCode != MFRC522_NTAG424DNA::DNA_STATUS_TIMEOUT)
      // Errors other than timeout appear often when slowly approaching a card to the reader.
      // When it happens, the card has to be deselected and woken up.
      deselectAndWakeupA = true;
    return;
  }
  
  byte keyNumber = 0;
  byte authKey[16] = {}; // all zeros on delivery
  byte rndA[16];
  generateRndA(rndA);
  dna_statusCode = ntag.DNA_AuthenticateEV2First(keyNumber, authKey, rndA);
  if (dna_statusCode != MFRC522_NTAG424DNA::DNA_STATUS_OK){
    Serial.print(F("AuthenticateEV2First STATUS NOT OK: "));
    Serial.println(dna_statusCode);
    if (dna_statusCode != MFRC522_NTAG424DNA::DNA_STATUS_TIMEOUT)
      // Errors other than timeout appear often when slowly approaching a card to the reader.
      // When it happens, the card has to be deselected and woken up.
      deselectAndWakeupA = true;
    return;
  }
  
  byte backData[29];
  byte backLen = 29;
  dna_statusCode = ntag.DNA_Mac_GetVersion(backData, &backLen);
  if (dna_statusCode != MFRC522_NTAG424DNA::DNA_STATUS_OK){
    Serial.print(F("Mac_GetVersion STATUS NOT OK: "));
    Serial.println(dna_statusCode);
    if (dna_statusCode != MFRC522_NTAG424DNA::DNA_STATUS_TIMEOUT)
      // Errors other than timeout appear often when slowly approaching a card to the reader.
      // When it happens, the card has to be deselected and woken up.
      deselectAndWakeupA = true;
  }else{
    Serial.print(F("Hardware:"));
    Serial.print(F("\n VendorID:"));
    printHex(&backData[0], 1);
    Serial.print(F("\n Type:"));
    printHex(&backData[1], 1);
    Serial.print(F("\n SubType:"));
    printHex(&backData[2], 1);
    Serial.print(F("\n MajorVersion:"));
    printHex(&backData[3], 1);
    Serial.print(F("\n MinorVersion:"));
    printHex(&backData[4], 1);
    Serial.print(F("\n StorageSize:"));
    printHex(&backData[5], 1);
    Serial.print(F("\n Protocol:"));
    printHex(&backData[6], 1);
    
    Serial.print(F("\nSoftware:"));
    Serial.print(F("\n VendorID:"));
    printHex(&backData[7], 1);
    Serial.print(F("\n Type:"));
    printHex(&backData[8], 1);
    Serial.print(F("\n SubType:"));
    printHex(&backData[9], 1);
    Serial.print(F("\n MajorVersion:"));
    printHex(&backData[10], 1);
    Serial.print(F("\n MinorVersion:"));
    printHex(&backData[11], 1);
    Serial.print(F("\n StorageSize:"));
    printHex(&backData[12], 1);
    Serial.print(F("\n Protocol:"));
    printHex(&backData[13], 1);
    
    Serial.print(F("\nOther:"));
    Serial.print(F("\n UID:"));
    printHex(&backData[14], 7);
    Serial.print(F("\n BatchNo:"));
    printHex(&backData[21], 4);
    
    // BatchNo(4 bits) FabKey(4 bits)
    Serial.print(F("\n BatchNo/FabKey:"));
    printHex(&backData[25], 1);
    
    //byte CWProd = backData[26] & 0b01111111;
    // FabKey(1 bit) CWProd(7 bits)
    Serial.print(F("\n FabKey/CWProd:"));
    printHex(&backData[26], 1);
    
    Serial.print(F("\n YearProd:"));
    printHex(&backData[27], 1);
    if (backLen == 29){
      Serial.print(F("\n FabKeyID:"));
      printHex(&backData[28], 1);
    }
    Serial.println();
  }
  
}

void generateRndA(byte *backRndA) {
  for (byte i = 0; i < 16; i++)
    backRndA[i] = random(0xFF);
}

void printHex(byte *buffer, uint16_t bufferSize) {
  for (uint16_t i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}
