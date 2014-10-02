#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>
#include <freefare.h>

int main(int argc, char *argv[]) {
  nfc_device *pnd = NULL;
  MifareTag *tags = NULL;
  struct mifare_desfire_version_info info;
  uint8_t settings;
  uint8_t max_keys;
  uint8_t version;
  uint32_t size;

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

  if(mifare_desfire_get_version (tags[0], &info) != OPERATION_OK) {
    printf("can't get info on tag\n");
    mifare_desfire_disconnect(tags[0]);
    freefare_free_tags(tags);
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  } else {
    printf ("UID:                      0x%02x%02x%02x%02x%02x%02x%02x\n", info.uid[0], info.uid[1], info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
    printf ("Batch number:             0x%02x%02x%02x%02x%02x\n", info.batch_number[0], info.batch_number[1], info.batch_number[2], info.batch_number[3], info.batch_number[4]);
    printf ("Production date:          week %x, 20%02x\n", info.production_week, info.production_year);
    printf ("Hardware Information:\n");
    printf ("    Vendor ID:            0x%02x\n", info.hardware.vendor_id);
    printf ("    Type:                 0x%02x\n", info.hardware.type);
    printf ("    Subtype:              0x%02x\n", info.hardware.subtype);
    printf ("    Version:              %d.%d\n", info.hardware.version_major, info.hardware.version_minor);
    printf ("    Storage size:         0x%02x (%s%d bytes)\n", info.hardware.storage_size, (info.hardware.storage_size & 1) ? ">" : "=", 1 << (info.hardware.storage_size >> 1));
    printf ("    Protocol:             0x%02x\n", info.hardware.protocol);
    printf ("Software Information:\n");
    printf ("    Vendor ID:            0x%02x\n", info.software.vendor_id);
    printf ("    Type:                 0x%02x\n", info.software.type);
    printf ("    Subtype:              0x%02x\n", info.software.subtype);
    printf ("    Version:              %d.%d\n", info.software.version_major, info.software.version_minor);
    printf ("    Storage size:         0x%02x (%s%d bytes)\n", info.software.storage_size, (info.software.storage_size & 1) ? ">" : "=", 1 << (info.software.storage_size >> 1));
    printf ("    Protocol:             0x%02x\n", info.software.protocol);
  }

  if(mifare_desfire_get_key_settings(tags[0], &settings, &max_keys) == OPERATION_OK) {
    printf ("Master Key settings (0x%02x):\n", settings);
    printf ("    0x%02x configuration changeable;\n", settings & 0x08);
    printf ("    0x%02x PICC Master Key not required for create / delete;\n", settings & 0x04);
    printf ("    0x%02x Free directory list access without PICC Master Key;\n", settings & 0x02);
    printf ("    0x%02x Allow changing the Master Key;\n", settings & 0x01);
  } else if (mifare_desfire_last_picc_error(tags[0]) == AUTHENTICATION_ERROR) {
    printf ("Master Key settings: LOCKED\n");
  } else {
    printf("get settings error, other error\n");
  }

  if(mifare_desfire_get_key_version(tags[0], 0, &version) == OPERATION_OK) {
    printf("Master Key version: %d (0x%02x)\n", version, version);
  } else {
    printf("can't get Master key version\n");
  }

  printf ("Free memory: ");
  if(mifare_desfire_free_mem(tags[0], &size) == OPERATION_OK) {
    printf ("%d bytes\n", size);
  } else {
    printf ("unknown\n");
  }

  mifare_desfire_disconnect(tags[0]);
  freefare_free_tags(tags);
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
} 
