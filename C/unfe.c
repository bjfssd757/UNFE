#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define FILE_IDENTIFIER {0x55, 0x4e, 0x46, 0x45} // "UNFE"
#define FILE_VERSION 1

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

typedef struct {
    uint8_t identifier[4];
    uint8_t version;
    uint32_t file_size;

    uint32_t header_offset;
    uint32_t header_size;

    uint32_t payload_offset;
    uint32_t payload_size;

    uint32_t meta_offset;
    uint32_t meta_size;

    uint8_t reserved[32];
    uint32_t checksum;
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
UNFE_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

typedef struct {
    uint32_t architecture_id;
    uint32_t payload_offset;
    uint32_t payload_size;
} FilePayloadDescriptor_t;

typedef enum {
    OK = 0,
    ERROR_MALLOC_FAILED,
    ERROR_MEMORY_OVERFLOW,
    ERROR_INVALID_ARGUMENT
} FileResult_t;


UNFE_t get_info(const uint8_t* file_buffer) {
    return *(const UNFE_t*)file_buffer;
}

uint32_t calculate_checksum(const uint8_t* data, size_t len) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < len; i++) {
        checksum += data[i];
    }
    return checksum;
}

FileResult_t make_file(
    const uint8_t* header_data, size_t header_len,
    const uint8_t* payload_data, size_t payload_len,
    const uint8_t* meta_data, size_t meta_len,
    uint8_t** out_file
) {
    if (!out_file) {
        return ERROR_INVALID_ARGUMENT;
    }

    const size_t main_header_size = sizeof(UNFE_t);
    size_t current_offset = main_header_size;

    size_t header_content_offset = (header_len > 0) ? current_offset : 0;
    current_offset += header_len;

    size_t payload_content_offset = (payload_len > 0) ? current_offset : 0;
    current_offset += payload_len;

    size_t meta_content_offset = (meta_len > 0) ? current_offset : 0;
    current_offset += meta_len;
    
    const size_t total_file_size = current_offset;

    if ( (main_header_size > SIZE_MAX - header_len) ||
         (main_header_size + header_len > SIZE_MAX - payload_len) ||
         (main_header_size + header_len + payload_len > SIZE_MAX - meta_len) ) {
        return ERROR_MEMORY_OVERFLOW;
    }

    uint8_t* file_buffer = malloc(total_file_size);
    if (!file_buffer) {
        return ERROR_MALLOC_FAILED;
    }

    UNFE_t* main_header = (UNFE_t*)file_buffer;
    const uint8_t identifier[] = FILE_IDENTIFIER;
    memcpy(main_header->identifier, identifier, sizeof(identifier));
    
    main_header->version = FILE_VERSION;
    main_header->file_size = total_file_size;

    main_header->header_offset = header_content_offset;
    main_header->header_size = header_len;

    main_header->payload_offset = payload_content_offset;
    main_header->payload_size = payload_len;

    main_header->meta_offset = meta_content_offset;
    main_header->meta_size = meta_len;
    
    memset(main_header->reserved, 0, sizeof(main_header->reserved));
    main_header->checksum = 0;

    if (header_data && header_len > 0) {
        memcpy(file_buffer + header_content_offset, header_data, header_len);
    }
    if (payload_data && payload_len > 0) {
        memcpy(file_buffer + payload_content_offset, payload_data, payload_len);
    }
    if (meta_data && meta_len > 0) {
        memcpy(file_buffer + meta_content_offset, meta_data, meta_len);
    }

    main_header->checksum = calculate_checksum(file_buffer, total_file_size);

    *out_file = file_buffer;
    return OK;
}

bool is_unfe_file(const uint8_t* file_buffer, size_t buffer_len) {
    if (!file_buffer || buffer_len < sizeof(UNFE_t)) {
        return false;
    }

    const uint8_t expected_identifier[] = FILE_IDENTIFIER;
    const UNFE_t* header = (const UNFE_t*)file_buffer;

    if (memcmp(header->identifier, expected_identifier, sizeof(expected_identifier)) != 0) {
        return false;
    }
    if (header->file_size != buffer_len) {
        return false;
    }

    uint32_t stored_checksum = header->checksum;
    UNFE_t temp_header = *header;
    temp_header.checksum = 0;

    uint8_t* temp_buffer = malloc(buffer_len);
    if (!temp_buffer) return false;
    
    memcpy(temp_buffer, file_buffer, buffer_len);
    memcpy(temp_buffer, &temp_header, sizeof(UNFE_t));
    
    uint32_t calculated_checksum = calculate_checksum(temp_buffer, buffer_len);
    free(temp_buffer);

    return stored_checksum == calculated_checksum;
}

void free_file(uint8_t* file) {
    free(file);
}