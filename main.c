#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_BUFF_SIZE 256
#define INITIAL_CAPACITY 2
#define ALL_SIZE 4

#define RSA_SIZE 512
#define AES_128_SIZE 176
#define AES_256_SIZE 240
#define TWOFISH_256_SIZE 4272
#define SERPENT_256_SIZE 560

void print_usage(void) {
    const char *const format = "Usage: dump_memory [options] file\n"
                               "Options:\n"
                               "  [-a|--aes] <file>      Use offset from <file> to zeroize AES keys.\n"
                               "  [-r|--rsa] <file>      Use offset from <file> to zeroize RSA keys.\n"
                               "  [-s|--serpent] <file>  Use offset from <file> to zeroize SERPENT keys.\n"
                               "  [-t|--twofish] <file>  Use offset from <file> to zeroize TWOFISH keys.\n"
                               "  [-o|--outfile] <file>  Place the output into <file>.\n"
                               "  [-v|--verbose]         Display extended logs.\n"
                               "  [-h|--help]            Display this information.\n";
    fprintf(stdout, format);
}

// IO
#define CHUNK_SIZE 1

typedef struct {
    FILE *fp;
    size_t file_size;
} FileHandler;

FileHandler open_file(const char *const filename, const char *const mode) {
    FileHandler file_handler = {.fp = NULL, .file_size = 0 };

    if (mode[0] == 'r') {
        struct stat st;
        int status = stat(filename, &st);
        if (status == -1) {
            perror("Error [open_file/stat]");
            return file_handler;
        }
        file_handler.file_size = (size_t) st.st_size;
    }
    

    file_handler.fp = fopen(filename, mode);
    if (file_handler.fp == NULL) {
        perror("Error [open_file/fopen]");
        return file_handler;
    }

    return file_handler;
}

unsigned char* read_file(const FileHandler *const file) {
    if (file->fp == NULL) {
        fprintf(stderr, "Error [read_file]: File is not open\n");
        return NULL;
    }

    unsigned char *buffer = calloc(file->file_size + 1, sizeof(unsigned char));
    if (buffer  == NULL) {
        perror("Error [read_file/calloc]");
        return NULL;
    }

    size_t file_size = fread(buffer, CHUNK_SIZE, file->file_size, file->fp);
    if (file_size != file->file_size || ferror(file->fp)) {
        perror("Error [read_file/fread]");
        fprintf(stderr, "Total file size: %zu\n", file->file_size);
        fprintf(stderr, "Read file size: %zu\n", file_size);
        return NULL;
    }

    fprintf(stderr, "Read file size: %zu\n", file_size);

    return buffer;
}

bool save_file(const char *const filepath, unsigned char *buffer, size_t file_size) {
    FileHandler file = open_file(filepath, "wb");
    if (file.fp == NULL) {
        fprintf(stderr, "Program terminated.\n");
        return false;
    }
    size_t written_bytes = fwrite(buffer, CHUNK_SIZE, file_size, file.fp);
    if (written_bytes != file_size) {
        perror("Error [save_file/fwrite]");
        fclose(file.fp);
        return false;
    }

    printf("Successfully wrote a total of %zu bytes to '%s'.\n", written_bytes, filepath);

    if (fclose(file.fp) != 0) {
        perror("Error closing file");
    }

    return true;
}

// utils
#define MAX_LINE_SIZE 256

typedef enum {
    AES,
    RSA,
    SERPENT,
    TWOFISH,
} Algorithm;

typedef struct {
    size_t offset;
    size_t key_size;
} OffsetPair;

typedef struct {
    OffsetPair *data;
    size_t size;
    size_t capacity;
} OffsetArray;

OffsetArray* parse_offset(const char *const file_path, Algorithm algorithm) {
    FileHandler file = open_file(file_path, "r");
    if (file.fp == NULL) {
        fprintf(stderr, "Program terminated.\n");
        return NULL;
    }

    char line_buffer[MAX_LINE_SIZE];
    size_t line_number = 0;

    OffsetArray *offset_array = malloc(sizeof(OffsetArray));
    offset_array->data = NULL;
    offset_array->size = 0;
    offset_array->capacity = 0;

    while (fgets(line_buffer, MAX_LINE_SIZE, file.fp) != NULL) {
        line_number++;
        char *comma_pos;
        char *endptr;

        // null-terminate line
        size_t eol_pos = strcspn(line_buffer, "\r\n");
        line_buffer[eol_pos] = '\0';

        // find comma
        comma_pos = strchr(line_buffer, ',');
        if (comma_pos == NULL) {
            fprintf(stderr, "Warning: Skipping line %zu: No comma found: '%s'\n", line_number, line_buffer);
            continue;
        }

        // parse offset
        *comma_pos = '\0';
        errno = 0;
        size_t offset = strtoull(line_buffer, &endptr, 16);

        if (errno != 0) {
            perror("Warning: Error parsing offset on line");
            fprintf(stderr, "\t\tLine %zu: '%s'\n", line_number, line_buffer);
            continue;
        }
        if (*endptr != '\0') {
            fprintf(stderr, "Warning: Invalid characters found while parsing offset on line %zu: '%s'\n", line_number, line_buffer);
            continue;
        }

        // parse key size
        errno = 0;
        size_t key_size = strtoull(comma_pos + 1, &endptr, 10);

        if (errno != 0) {
            perror("Warning: Error parsing key size on line");
            fprintf(stderr, "\tLine %zu: '%s'\n", line_number, line_buffer);
            continue;
        }
        if (*endptr != '\0') {
            fprintf(stderr, "Warning: Invalid characters found while parsing key size on line %zu: '%s'\n", line_number, line_buffer);
            continue;
        }

        // save offset and key size
        if (offset_array->size >= offset_array->capacity) {
            size_t new_capacity = (offset_array->capacity == 0) ? INITIAL_CAPACITY : offset_array->capacity * 2;
            OffsetPair *temp_offset = realloc(offset_array->data, new_capacity * sizeof(OffsetPair));

            if (temp_offset == NULL) {
                perror("Error during reallocating memory [parse/realloc]");
                free(offset_array->data);
                fclose(file.fp);
                return NULL;
            }

            offset_array->data = temp_offset;
            offset_array->capacity = new_capacity;
        }

        offset_array->data[offset_array->size].offset = offset;
        switch (algorithm) {
            case AES:
                if (key_size == 128)
                    offset_array->data[offset_array->size].key_size = AES_128_SIZE;
                else if (key_size == 256)
                    offset_array->data[offset_array->size].key_size = AES_256_SIZE;
                else {
                    fprintf(stderr, "Warning: Invalid key size\n");
                    continue;
                }
                break;
            case RSA:
                offset_array->data[offset_array->size].key_size = RSA_SIZE;
                break;
            case SERPENT:
                offset_array->data[offset_array->size].key_size = SERPENT_256_SIZE;
                break;
            case TWOFISH:
                offset_array->data[offset_array->size].key_size = TWOFISH_256_SIZE;
                break;
            default:
                // unreachable
                break;
        }
        
        offset_array->size++;

        printf("\tLine %02zu: offset = 0x%08zx, key size = %zu\n", line_number, offset_array->data[offset_array->size-1].offset, offset_array->data[offset_array->size-1].key_size);
    }

    if (ferror(file.fp)) {
        perror("Error reading from file");
        return NULL;
    }

    fclose(file.fp);
    printf("Finished parsing.\n");

    return offset_array;
}

bool zero_buffer(unsigned char *buffer, const OffsetArray *const offsets, const size_t buff_size) {
    for (size_t i = 0; i < offsets->size; i++) {
        OffsetPair offset = offsets->data[i];

        if (offset.offset >= buff_size) {
            printf("Warning: Offset %zu is out of bounds for data size %zu\n", offset.offset, buff_size);
        }

        memset((void *)(buffer + offset.offset), 0, offset.key_size);
    }
    return true;
}



int main(int argc, char *argv[]) {
    const char *mem_filepath = NULL;
    const char *output_filepath = "./mem_dump_zeros.mem";

    const char *aes_filepath = NULL;
    const char *rsa_filepath = NULL;
    const char *serpent_filepath = NULL;
    const char *twofish_filepath = NULL;

    struct option longopts[] = {
        {"aes", required_argument, NULL, 'a'},
        {"rsa", required_argument, NULL, 'r'},
        {"serpent", required_argument, NULL, 's'},
        {"twofish", required_argument, NULL, 't'},
        {"outfile", required_argument, NULL, 'o'},
        {"verbose", required_argument, NULL, 'v'},
        {"help", required_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "a:r:s:t:o:vh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'a':
                aes_filepath = optarg;
                printf("\t--aes %s\n", aes_filepath);
                break;
            case 'r':
                rsa_filepath = optarg;
                printf("\t--rsa %s\n", rsa_filepath);
                break;
            case 's':
                serpent_filepath = optarg;
                printf("\t--serpent %s\n", serpent_filepath);
                break;
            case 't':
                twofish_filepath = optarg;
                printf("\t--twofish %s\n", twofish_filepath);
                break;
            case 'o':
                output_filepath = optarg;
                printf("\t--outfile %s\n", output_filepath);
                break;
            case 'v':
                // TODO
                break;
            case 'h':
                print_usage();
                return EXIT_FAILURE;
            default:
                fprintf(stderr, "Try 'dump_mem --help' for more information.\n");
                return EXIT_FAILURE;
        }
    }
    if (argc - optind != 1) {
        fprintf(stderr, "Error: Incorrect number of given filepath\n");
        return EXIT_FAILURE;
    }

    mem_filepath = argv[optind];

    printf("Opening memory from %s\n", mem_filepath);
    FileHandler mem_file = open_file(mem_filepath, "rb");
    if (mem_file.fp == NULL) {
        fprintf(stderr, "Program terminated.\n");
        return EXIT_FAILURE;
    }
    printf("Memory successfully opened.\n");
    
    printf("Loading memory to buffer.\n");
    unsigned char *buffer = read_file(&mem_file);
    if (buffer == NULL) {
        fprintf(stderr, "Program terminated.\n");
        
        if (mem_file.fp == NULL)
            fclose(mem_file.fp);

        return EXIT_FAILURE;
    }
    printf("Memory successfully loaded.\n");
    fclose(mem_file.fp);

    if (aes_filepath != NULL) {
        printf("Parsing offsets for AES.\n");
        OffsetArray *offset_array = parse_offset(aes_filepath, AES);

        printf("Zeroing based on AES offsets.\n");
        zero_buffer(buffer, offset_array, mem_file.file_size);
        printf("Zeroing completed.\n");
    }

    if (rsa_filepath != NULL) {
        printf("Parsing offsets for RSA.\n");
        OffsetArray *offset_array = parse_offset(rsa_filepath, RSA);

        printf("Zeroing based on RSA offsets.\n");
        zero_buffer(buffer, offset_array, mem_file.file_size);
        printf("Zeroing completed.\n");
    }

    if (serpent_filepath != NULL) {
        printf("Parsing offsets for SERPENT.\n");
        OffsetArray *offset_array = parse_offset(serpent_filepath, SERPENT);

        printf("Zeroing based on SERPENT offsets.\n");
        zero_buffer(buffer, offset_array, mem_file.file_size);
        printf("Zeroing completed.\n");
    }

    if (twofish_filepath != NULL) {
        printf("Parsing offsets for TWOFISH.\n");
        OffsetArray *offset_array = parse_offset(twofish_filepath, TWOFISH);

        printf("Zeroing based on TWOFISH offsets.\n");
        zero_buffer(buffer, offset_array, mem_file.file_size);
        printf("Zeroing completed.\n");
    }

    printf("Loading buffer into file.\n");
    save_file(output_filepath, buffer, mem_file.file_size);
}