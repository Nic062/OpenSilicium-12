#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>
#include <freefare.h>

MifareClassicKey keymap[16];

MifareClassicKey keys[] = {
  { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
  { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
  { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
  { 0xff,0xff,0xff,0xff,0xff,0xff },
  { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
  { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
  { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
  { 0x00,0x00,0x00,0x00,0x00,0x00 }
};

static void print_hex(MifareClassicBlock blkData, const size_t szBytes) {
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf("%02x ", (uint8_t)blkData[szPos]);
  }
  printf("\n");
}


int main(int argc, const char *argv[])
{
  nfc_device *pnd;
  //nfc_target nt;
  MifareTag *tags = NULL;
  int i,j,k;
  int nbrsect=0;

  MifareClassicBlock data;

  // Allocate only a pointer to nfc_context
  nfc_context *context;

  // Initialize libnfc and set the nfc_context
  nfc_init(&context);
  if (context == NULL) {
    printf("Unable to init libnfc\n");
    exit(EXIT_FAILURE);
  }

  // Open, using the first available NFC device which can be in order of selection:
  //   - default device specified using environment variable or
  //   - first specified device in libnfc.conf (/etc/nfc) or
  //   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
  //   - first auto-detected (if feature is not disabled in libnfc.conf) device
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    printf("ERROR: %s\n", "Unable to open NFC device.");
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

  tags = freefare_get_tags(pnd);

  if (!tags) {
    printf("no Mifare classic\n");
  } else {
    for (i = 0; tags[i]; i++) {
      switch(freefare_get_tag_type(tags[i])) {
	case CLASSIC_1K:
	  printf("%u : Mifare 1k (S50) : %s\n", i, freefare_get_tag_uid(tags[i]));
	  nbrsect=16;
	  break;
	case CLASSIC_4K:
	  printf("%u : Mifare 4k (S70) : %s\n", i, freefare_get_tag_uid(tags[i]));
	  nbrsect=40;
	  break;
	default:
	  printf("%u : other ISO14443A tag : %s\n", i, freefare_get_tag_uid(tags[i]));
      }
    }
  }

  if (!tags[0]) {
    printf("no tag found !\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf ("Found %s\n", freefare_get_tag_friendly_name (tags[0]));

  /*
     MifareClassicBlockNumber dablock = 1;
     if(mifare_classic_connect(tags[0]) == OPERATION_OK) {
     printf("Connected !\n");
     if(mifare_classic_authenticate(tags[0], dablock, keys[0], MFC_KEY_A) == OPERATION_OK) {
     printf("Authenticated !\n");
     if(mifare_classic_get_data_block_permission (tags[0], dablock, MCAB_R|MCAB_W, MFC_KEY_A))
     printf("i can READ block %d with key A\n", dablock);
     if(mifare_classic_get_trailer_block_permission (tags[0], ((dablock)/4)*4+3, MCAB_READ_KEYB, MFC_KEY_B))
     printf("i can READ KEY A in trailer\n");
     }
     }
   */

  for(i=0; i<nbrsect; i++) {
    for(j=0; j < sizeof(keys)/sizeof(keys[0]); j++) {
      if((mifare_classic_connect(tags[0]) == OPERATION_OK) && 
	  (mifare_classic_authenticate(
				       tags[0], 
				       mifare_classic_sector_last_block(i), 
				       keys[j], 
				       MFC_KEY_A) == OPERATION_OK)) {
	printf("sector %02d auth with A[%d]\n", i, j);
	for(k=mifare_classic_sector_first_block(i); 
	    k<=mifare_classic_sector_last_block(i); k++) {
	  if(mifare_classic_read(tags[0], k, &data) == OPERATION_OK) {
	    print_hex(data,16);
	  } else {
	    printf("read error\n");
	  }
	}
	mifare_classic_disconnect(tags[0]);
	break;
      }
      mifare_classic_disconnect(tags[0]);
    }
    printf("\n");
  }
  printf("\n");

  freefare_free_tags(tags);

  // Close NFC device
  nfc_close(pnd);
  // Release the context
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
