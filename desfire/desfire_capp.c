#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>
#include <freefare.h>

int main(int argc, char *argv[]) {
  nfc_device *pnd = NULL;
  MifareTag *tags = NULL;

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

  uint8_t picc_key_data_null[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uint8_t key_data_null[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  //uint8_t mykey123[8] =      { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t mykey123[16] =      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

  MifareDESFireKey piccnullkey = mifare_desfire_des_key_new(picc_key_data_null);
  MifareDESFireKey nullkey = mifare_desfire_aes_key_new(key_data_null);
  //MifareDESFireKey mykey   = mifare_desfire_des_key_new(mykey123);
  MifareDESFireKey mykey   = mifare_desfire_aes_key_new(mykey123);

  if(mifare_desfire_select_application(tags[0],NULL) == OPERATION_OK) {
    printf("----\nMaster Application selected\n");
    if(mifare_desfire_authenticate(tags[0], 0, piccnullkey) == OPERATION_OK) {
      printf("Master auth ok\n");
      if(mifare_desfire_format_picc (tags[0]) != OPERATION_OK) {
	printf("Format error : %s\n", freefare_strerror(tags[0]));
	freefare_free_tags(tags);
	nfc_close(pnd);
	nfc_exit(context);
	exit(EXIT_FAILURE);
      } else {
	printf("tag formated\n");
      }
    }
  }


  /*
   * CREA APP
   */
  // select app NULL (master app)
  if(mifare_desfire_select_application(tags[0],NULL) == OPERATION_OK) {
    printf("----\nMaster Application selected\n");
    // auth master key
    if(mifare_desfire_authenticate(tags[0], 0, piccnullkey) == OPERATION_OK) {
      printf("Master auth ok\n");
      // create app AID 0x000001
      MifareDESFireAID myaid;
      myaid = mifare_desfire_aid_new(0x000001);
      if(mifare_desfire_create_application_aes(tags[0], myaid, 0x0f, 5) == OPERATION_OK) {
	printf("Application created\n");
	// select app AID 0x000001
	if(mifare_desfire_select_application(tags[0],myaid) == OPERATION_OK) {
	  printf("Application selected\n");
	  // auth app AID 0x000001
	  if(mifare_desfire_authenticate(tags[0], 0, nullkey) == OPERATION_OK) {
	    printf("App auth ok\n");

	    // change key 4
	    if(mifare_desfire_change_key(tags[0], 4, mykey, nullkey) == OPERATION_OK) {
	      printf("key changed !\n");
	    } else {
	      printf("ERROR key change : %s!\n", freefare_strerror(tags[0]));
	    }

	    if(mifare_desfire_create_std_data_file(tags[0], 1, MDCM_ENCIPHERED, MDAR(MDAR_KEY4,MDAR_FREE,MDAR_DENY,MDAR_FREE), 20) == OPERATION_OK) {
	      printf("file created\n");
	      const char *s= "Hello World";
	      // file 1 write data
	      if(mifare_desfire_write_data(tags[0], 1, 0, strlen(s), s) == strlen(s)) {
		printf("file write ok\n");
	      }
	    }
	  }
	}
      }
      free(myaid);
    }
  }

  mifare_desfire_key_free(mykey);
  mifare_desfire_key_free(nullkey);
  mifare_desfire_key_free(piccnullkey);

  mifare_desfire_disconnect(tags[0]);
  freefare_free_tags(tags);
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
} 
