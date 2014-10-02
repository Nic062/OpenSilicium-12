/*
 To compile this simple example:
 gcc -o quick_start_example1 quick_start_example1.c -lnfc

 https://matt.bionicmessage.net/blog/2010/02/07/Poking%20around%20on%20a%20Mifare%20card:%20LibNFC%20crash%20course
*/

#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>
#include <freefare.h>

MifareClassicKey keys[] = {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
};

MifareClassicBlock default_trailer_block = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* Key A */
	0xff, 0x07, 0x80,                    /* Access bits */
	0x69,                                /* GPB */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff   /* Key B */
};

/*
static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf("%02x ", pbtData[szPos]);
  }
  printf("\n");
}
*/

int main(int argc, const char *argv[])
{
  nfc_device *pnd;
//  nfc_target nt;
//  static mifare_param mp;
  int i, j;

  MifareTag *tags = NULL;
  int error = 0;
  MifareClassicBlock dablock;
//  MifareClassicBlock mydata = {0x00,0x00,0x00,0x42,   0xff,0xff,0xff,0xbd,   0x00,0x00,0x00,0x42,   0,0xff,0x00,0xff};

  MifareClassicBlock my_trailer_block;
  MifareClassicKey my_key_A = { 0xff,0xff,0xff,0xff,0xff,0xff };
  MifareClassicKey my_key_B = { 0xff,0xff,0xff,0xff,0xff,0xff };


  // Allocate only a pointer to nfc_context
  nfc_context *context;

  // Initialize libnfc and set the nfc_context
  nfc_init(&context);
  if (context == NULL) {
    printf("Unable to init libnfc (malloc)\n");
    exit(EXIT_FAILURE);
  }

  // Display libnfc version
  const char *acLibnfcVersion = nfc_version();
  (void)argc;
  printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

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
  // Set opened NFC device to initiator mode
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

  // Poll for a ISO14443A (MIFARE) tag
  /*
  const nfc_modulation nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
  };

  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0) {
    printf("The following (NFC) ISO14443A tag was found:\n");
    printf("    ATQA (SENS_RES): ");
    print_hex(nt.nti.nai.abtAtqa, 2);
    printf("       UID (NFCID%c): ", (nt.nti.nai.abtUid[0] == 0x08 ? '3' : '1'));
    print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
    printf("      SAK (SEL_RES): ");
    print_hex(&nt.nti.nai.btSak, 1);
    if (nt.nti.nai.szAtsLen) {
      printf("          ATS (ATR): ");
      print_hex(nt.nti.nai.abtAts, nt.nti.nai.szAtsLen);
    }
  }
  */

  tags = freefare_get_tags(pnd);
  if (!tags) {
	  printf("no Mifare classic\n");
  } else {
	  for (i = 0; (!error) && tags[i]; i++) {
		  if (freefare_get_tag_type(tags[i]) == CLASSIC_1K)
			  printf("%u : Mifare 1k (S50)\n",i);
		  if (freefare_get_tag_type(tags[i]) == CLASSIC_4K)
			  printf("%u : Mifare 4k (S70)\n",i);
	  }
	  if(mifare_classic_connect(tags[0])==0) {
		  printf("connected\n");
		  if(mifare_classic_authenticate(tags[0], 1,keys[0],MFC_KEY_B) == OPERATION_OK) {
			  printf("Authenticated !\n");

			  if(mifare_classic_read (tags[0], 1, &dablock) == OPERATION_OK) {
			  	printf("Block readed\n");
				for(j=0; j<16; j++) {
					printf("%02X ", dablock[j]);
				}
				printf("\n");
			  } else {
				  printf("Auth error : %s\n", freefare_strerror(tags[0]));
			  }

			  if(mifare_classic_get_data_block_permission (tags[0], 1, MCAB_R, MFC_KEY_A))
				  printf("i can READ this block with B\n");
			  if(mifare_classic_get_data_block_permission (tags[0], 1, MCAB_W, MFC_KEY_A))
				  printf("i can WRITE this block with B\n");
			  if(mifare_classic_get_data_block_permission (tags[0], 1, MCAB_I, MFC_KEY_A))
				  printf("i can INC this block with B\n");
			  if(mifare_classic_get_data_block_permission (tags[0], 1, MCAB_D, MFC_KEY_A))
				  printf("i can DEC this block with B\n");

			  printf("---\n");

			  /* trailer = ((block) / 4) * 4 + 3; */
			  if(mifare_classic_get_trailer_block_permission (tags[0], 3, MCAB_READ_KEYA, MFC_KEY_A))
				  printf("i can READ KEY A in trailer\n");
			  if(mifare_classic_get_trailer_block_permission (tags[0], 3, MCAB_WRITE_KEYA, MFC_KEY_A))
				  printf("i can WRITE KEY A in trailer\n");
			  if(mifare_classic_get_trailer_block_permission (tags[0], 3, MCAB_READ_ACCESS_BITS, MFC_KEY_A))
				  printf("i can READ ACCESS BITS in trailer\n");
			  if(mifare_classic_get_trailer_block_permission (tags[0], 3, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A))
				  printf("i can WRITE ACCESS BITS in trailer\n");
			  if(mifare_classic_get_trailer_block_permission (tags[0], 3, MCAB_READ_KEYB, MFC_KEY_A))
				  printf("i can READ KEYB in trailer\n");
			  if(mifare_classic_get_trailer_block_permission (tags[0], 3, MCAB_WRITE_KEYB, MFC_KEY_A))
				  printf("i can WRITE KEYB in trailer\n");

			  /*
			  if(mifare_classic_write (tags[0], 1, mydata) == 0) {
				  printf("write ok\n");
			  }
			  */
			  if(mifare_classic_init_value (tags[0], 1, 0x42, 00) == 0) {
				  printf("init value bloc ok\n");
			  }

			  /* compose trailer block */
			  /*                                                          ab0    ab1     ab2   abt    gpb    */
			  /* abt = C_100 = 4 = 100 = c3c2c1  != datasheet c1c2c3*/
			  //mifare_classic_trailer_block (&my_trailer_block, my_key_A, C_000, C_011, C_000, C_100,  0x69, my_key_B);
			  mifare_classic_trailer_block (&my_trailer_block, my_key_A, C_000, C_000, C_000, C_100,  0x69, my_key_B);
			  for(j=0; j<16; j++) {
				  printf("%02X ", my_trailer_block[j]);
			  }
			  printf("\n");
			  if(mifare_classic_write (tags[0], 3, my_trailer_block) == 0) {
				  printf("trailer write ok\n");
			  }
			  /*
			  if(mifare_classic_decrement(tags[0], 1, 1) == OPERATION_OK) {
				  printf("decrement ok\n");
			  } else {
				  printf("Decrement error : %s\n", freefare_strerror(tags[0]));
			  }

			  if(mifare_classic_transfer (tags[0], 1) == OPERATION_OK) {
				  printf("transfer ok\n");
			  } else {
				  printf("Transfert error : %s\n", freefare_strerror(tags[0]));
			  }

			  if(mifare_classic_read(tags[0], 1, &dablock) == OPERATION_OK) {
			  	printf("Block readed\n");
				for(j=0; j<16; j++) {
					printf("%02X ", dablock[j]);
				}
				printf("\n");
			  } else {
				  printf("Read error : %s\n", freefare_strerror(tags[0]));
			  }
			  */

		  } else {
			  printf("Erreur : %s\n", freefare_strerror(tags[0]));
		  }
		  mifare_classic_disconnect(tags[0]);
	  }
  }



/*
  for(i=0; i<1; i++) {
    for(j=0; j<8; j++) {
      memcpy(mp.mpa.abtKey, &keys[j*6], 6);
      res = nfc_initiator_mifare_cmd(pnd, MC_AUTH_B, 0, &mp);
      if(res) {
        printf("sector %u / key %u : yes\n", i, j);
        continue;
      } else {
        printf("sector %u / key %u : no\n", i, j);
      }
    }
  }
*/

  /*
  // mifare parameters
  memcpy(mp.mpa.abtAuthUid,nt.nti.nai.abtUid,4);
  memcpy(mp.mpa.abtKey, &keys[0*6], 6);

  //                                           block
  res = nfc_initiator_mifare_cmd(pnd, MC_AUTH_A, 0, &mp);
  if(res) {
    printf("Auth success\n");
  } else {
    printf("Auth failed\n");
  }

  for(i=0; i<4; i++) {
    res = nfc_initiator_mifare_cmd(pnd, MC_READ, i, &mp);
    if(res) {
      print_hex(mp.mpd.abtData,16);
    } else {
      printf("Read failed\n");
    }
  }
  */



  // Close NFC device
  nfc_close(pnd);
  // Release the context
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
