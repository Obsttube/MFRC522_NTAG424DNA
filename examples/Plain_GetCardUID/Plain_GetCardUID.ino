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

void setup() { 
  Serial.begin(9600);
  SPI.begin();
  ntag.PCD_Init();
  
  // wait one second for the Serial to connect (recommended on NodeMCU / ESP8266, can be removed on Arduino Uno)
  delay(1000);
  Serial.println(F("POWER ON"));
}
 
void loop() {
  
  if (!ntag.PICC_IsNewCardPresent() || !ntag.PICC_ReadCardSerial())
    return;
  
  Serial.println(F("Card ID:"));
  byte UID[7];
  ntag.DNA_Plain_GetCardUID(UID);
  printHex(UID, 7);
  Serial.println();
  
}

void printHex(byte *buffer, uint16_t bufferSize) {
  for (uint16_t i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}
