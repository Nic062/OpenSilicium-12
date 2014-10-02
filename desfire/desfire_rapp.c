#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>
#include <freefare.h>

int main(int argc, char *argv[]) {
  nfc_device *pnd = NULL;
  MifareTag *tags = NULL;
  uint8_t version;

  MifareDESFireAID *aids = NULL;
  size_t aids_count;

  uint8_t *files = NULL;
  size_t files_count;
  struct mifare_desfire_file_settings fsettings;

  int i,j,k;

  nfc_context *context;
  nfc_init (&context);
  if (context == NULL) {
    printf("Unable to init libnfc\n");
    exit(EXIT_FAILURE);
  }

  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    printf("ERROR: %s\n", "Unable to open NFC device.");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

  tags = freefare_get_tags (pnd);
  if (!tags) {
    printf("no tag!\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if(freefare_get_tag_type(tags[0]) != DESFIRE) {
    printf("tag 0 is not DESFIRE!\n");
    freefare_free_tags(tags);
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if(mifare_desfire_connect(tags[0]) != OPERATION_OK) {
    printf("can't connect to tag!\n");
    freefare_free_tags(tags);
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if(mifare_desfire_get_application_ids(tags[0], &aids, &aids_count) == OPERATION_OK) {
    printf("got AIDs list : %u AID here\n", (unsigned int)aids_count);
    for(i=0; i<aids_count; i++) {
      if(mifare_desfire_select_application(tags[0],aids[i]) == OPERATION_OK) {
	printf("  AID[%d] : 0x%04x - selected\n", i, mifare_desfire_aid_get_aid(aids[i]));

	uint8_t ksetting;
	uint8_t maxkey;
	mifare_desfire_get_key_settings(tags[0], &ksetting, &maxkey);
	printf("  nbrkey pour cette app : %u\n", maxkey);
	printf("  key setting pour cette app : 0x%02x\n", ksetting);

	printf ("App Key settings (0x%02x):\n", ksetting);
	printf ("    0x%02x configuration changeable;\n", ksetting & 0x08);
	printf ("    0x%02x APP Master Key not required for create / delete;\n", ksetting & 0x04);
	printf ("    0x%02x Free directory list access without PICC Master Key;\n", ksetting & 0x02);
	printf ("    0x%02x Allow changing app master  Key;\n", ksetting & 0x01);


	for(k=0; k<maxkey; k++){
	  if(mifare_desfire_get_key_version(tags[0], k, &version) == OPERATION_OK) {
	    printf("  app Key  %d version: %d (0x%02x)\n", k,version, version);
	  } else {
	    printf("  can't get app key %d version\n",k);
	  }
	}

	if(mifare_desfire_get_file_ids(tags[0], &files, &files_count) == OPERATION_OK) {
	  printf("  got files list : %u files here\n", (unsigned int)files_count);
	  for(j=0; j<files_count; j++) {
	    printf("    file %d\n", j);
	    mifare_desfire_get_file_settings(tags[0], files[j], &fsettings);
	    switch (fsettings.file_type) {
	      case MDFT_STANDARD_DATA_FILE:
	      case MDFT_BACKUP_DATA_FILE:
		printf("      DATA_FILE : ");
		printf("%u bytes\n", fsettings.settings);
		break;
	      case MDFT_VALUE_FILE_WITH_BACKUP:
		printf("      VALUE_FILE\n");
		break;
	      case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
	      case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
		printf("      RECORD_FILE\n");
		break;
	    }
	  }
	}
	free(files);
      }
    }
    free(aids);
  } else {
    printf("can't get AIDs list\n");
  }

  printf("------------------------\n");

//  uint8_t picc_key_data_null[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//  uint8_t key_data_null[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uint8_t mykey123[16] =      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
//  MifareDESFireKey piccnullkey = mifare_desfire_des_key_new(picc_key_data_null);
//  MifareDESFireKey nullkey = mifare_desfire_aes_key_new(key_data_null);
  MifareDESFireKey mykey   = mifare_desfire_aes_key_new(mykey123);

  MifareDESFireAID myaid;
  myaid = mifare_desfire_aid_new(0x000001);
  if(mifare_desfire_select_application(tags[0], myaid) == OPERATION_OK) {
    printf("app 0x000001 selected\n");
    if(mifare_desfire_authenticate_aes(tags[0], 4, mykey) == OPERATION_OK) {
//    if(mifare_desfire_authenticate(tags[0], 0, nullkey) == OPERATION_OK) {
      printf("auth avec cle 4\n");
      char buffer[20];
      if(mifare_desfire_read_data(tags[0], 1, 0, 20, buffer) > 0) {
	printf("Data read : [%s]\n", buffer);
      } else {
	printf("read error : %s\n", freefare_strerror(tags[0]));
      }
    } else {
      printf("auth error : %s\n", freefare_strerror(tags[0]));
    }
  }

  mifare_desfire_disconnect(tags[0]);
  freefare_free_tags(tags);
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
} 


  /*
   * DATA WRITE
   */
  /*
  MifareDESFireAID myaid;
  myaid = mifare_desfire_aid_new(0x000001);
  if(mifare_desfire_select_application(tags[0],myaid) == OPERATION_OK) {
    printf("select app ok\n");
    uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    MifareDESFireKey key = mifare_desfire_des_key_new_with_version(key_data_null);
    if(mifare_desfire_authenticate(tags[0], 0, key) == OPERATION_OK) {
      printf("App auth ok\n");
      char buffer[20];
      if(mifare_desfire_read_data(tags[0], 1, 0, 0, buffer) == OPERATION_OK) {
	printf("Data read %s\n", buffer);
      } else {
	printf("Read Error\n");
      }
    }
  }
  */


