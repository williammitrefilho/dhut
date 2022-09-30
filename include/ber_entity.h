#ifndef BER_ENTITY_H

#define BER_ENTITY_H
typedef struct BerEntityList{
    
    unsigned short n_entities;
    struct BerEntity **entities;
} BerEntityList;

typedef struct BerEntity{
    
    struct BerEntity *parent;
    unsigned char type;    
    unsigned char *pData;
    unsigned short dataLen;
    BerEntityList *children;
    unsigned char allocMemory;
} BerEntity;

BerEntityList* ber_decode(unsigned char *data, unsigned short data_len, unsigned char use_data);
unsigned short free_entity(BerEntity *subject);
unsigned short free_entity_list(BerEntityList *list);
BerEntity* copy_ber_entity(BerEntity *entity);
#endif