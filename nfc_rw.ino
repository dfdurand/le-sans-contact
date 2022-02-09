#include <SPI.h>
#include <MFRC522.h>

/*Using Hardware SPI of Arduino */
/*MOSI (11), MISO (12) and SCK (13) are fixed */
/*configurations des pins SS et RST */
#define SS_PIN 10  /* pin esclave */
#define RST_PIN 7  /*pin Reset  */

/* Créer une instance de MFRC522 */
MFRC522 mfrc522(SS_PIN, RST_PIN);
/* Créer une instance de clé MIFARE_Key */
MFRC522::MIFARE_Key key;          

/* choisir le block à écrire */
/* attention au numéro de block........*/
int blockNum = 2;  
/* création d'un tableau de 16 octets */
/* données à écrire dans le programme */
byte blockData [16] = {"*message-secret*"};

/* tableau pour la lecture des données */
/* pour éviter toute pertes de données la taille estlégèrement supérieure */
byte bufferLen = 18;
byte readBlockData[18];

MFRC522::StatusCode status;  //instance du statut

void setup() 
{
  /* initialisation de la communication série */
  Serial.begin(9600);
  /* initialisation de la commucation/bus SPI */
  SPI.begin();
  /* Iinitialisation du module MFRC522 */
  mfrc522.PCD_Init();
  Serial.println("Scanner un Tag mifare pour l'écriture des donnees...");
}

void loop()
{
  /* phase depréparation à l'authentification*/
  /*toutes les clés sont initialisées à FFFFFFFFFFFFh xomme à la livraison du produit */
  for (byte i = 0; i < 6; i++)
  {
    key.keyByte[i] = 0xFF;
  }

  /* vérification d'une nouvelle carte*/
  /* et remise à zéro si aucune nouvelle carte n'est présente */
  if ( ! mfrc522.PICC_IsNewCardPresent())
  {
    return;
  }
  
  /* selection de la carte */
  if ( ! mfrc522.PICC_ReadCardSerial()) 
  {
    return;
  }
  Serial.print("\n");
  Serial.println("**carte detectee**");

  /*affichage de l'identifiant unique */

  Serial.print(F("Card UID:"));
  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.print("\n");

  /* Print type of card (for example, MIFARE 1K) */

  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
         
   /*phase d'écriture dans le block choisi */
   Serial.print("\n");
   Serial.println("ecriture des donnees dans le block...");
   WriteDataToBlock(blockNum, blockData);
   
   /* phase de lecture pour confirmation  */
   Serial.print("\n");
   Serial.println("lecture des donnees dans le block...");
   ReadDataFromBlock(blockNum, readBlockData);

   /* pour afficher l'ensemble des données dans le tag décommentez la ligne suivante */

   /*mfrc522.PICC_DumpToSerial(&(mfrc522.uid));*/
   
   /* affichache des données lues par le block */

   Serial.print("\n");
   Serial.print("donnees dans le block:");
   Serial.print(blockNum);
   Serial.print(" --> ");
   for (int j=0 ; j<16 ; j++)
   {
     Serial.write(readBlockData[j]);
   }
   Serial.print("\n");
}



void WriteDataToBlock(int blockNum, byte blockData[]) 
{
  /* authentification du block désiré par lecture de la  clé  A  */
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Authentification echouee: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    Serial.println("Authentification reussie");
  }

  
  /*écrire les données dans le block */
  status = mfrc522.MIFARE_Write(blockNum, blockData, 16);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Echec d'ecriture: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    Serial.println("données enrefistrées");
  }
  
}

void ReadDataFromBlock(int blockNum, byte readBlockData[]) 
{
  /** authentification du block désiré par lecture de la  clé  A  */
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK)
  {
     Serial.print("Echec de l'authentification : ");
     Serial.println(mfrc522.GetStatusCodeName(status));
     return;
  }
  else
  {
    Serial.println("Authentification reussie");
  }

  /* lecture des données dans le block */
  status = mfrc522.MIFARE_Read(blockNum, readBlockData, &bufferLen);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("EChec de lecture: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    Serial.println("Lecture des données reussie");  
  }
  
}



