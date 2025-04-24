#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define MAX_BUFF_SIZE 256
#define INITIAL_CAPACITY 2

#define RSA_LEN 512
#define AES_128_LEN 176
#define AES_256_LEN 240
#define TWOFISH_256_LEN 4272
#define SERPENT_256_LEN 560

static size_t buff_size = 0;
static size_t data_count = 0;

typedef struct {
    int key;
    size_t offset;
} OffsetPair;

unsigned char* read_file(FILE* stream) {
    fseek(stream, 0L, SEEK_END);
    buff_size = ftell(stream);
    rewind(stream);

    unsigned char *buffer;
    if ((buffer = calloc(buff_size + 1, sizeof(unsigned char))) == NULL) {
        perror("Memorry\n");
        exit(1);
    }

    if (fread(buffer, 1, buff_size, stream) != buff_size) {
        fprintf(stderr, "Reading error\n");
        fclose(stream);
        exit(1);
    }
    printf("Buff size: %zu\n", buff_size);
    fclose(stream);
    return buffer;
}

FILE* open_file(char* filename, char *mode) {
    struct stat st;

    FILE *file;

    if (stat(filename, &st) == -1) {
        perror("Error [stat]");
        exit(1);
    }

    if ((file = fopen(filename, mode)) == NULL) {
        perror("Error [fopen]");
        exit(1);
    }

    return file;
}

void save_file(char *filename, unsigned char *buffer, OffsetPair *data_offset, size_t offset_len) {
    FILE *output_file = NULL;
    size_t current_pos = 0;
    size_t total_bytes = 0;
    printf("data size: %zu\n", data_count);
    output_file = fopen(filename, "wb");
    if (output_file == NULL) {
        perror("Error while opeining file for writing\n");
        exit(1);
    }

    for (size_t i = 0; i < data_count; i++) {
        OffsetPair temp_offset = data_offset[i];
        if (offset_len == 0) {
            if (temp_offset.key == 128)
                offset_len = AES_128_LEN;
            if (temp_offset.key == 256)
                offset_len = AES_256_LEN;
        }

        printf("key: %d, offset: %zu\n", temp_offset.key, temp_offset.offset);

        if (temp_offset.offset >= buff_size) {
            printf("Warning: Offset %zu is out of bounds for data size %zu", temp_offset.offset, buff_size);
        }

        if (current_pos > temp_offset.offset) {
            printf("Warning: Overlapping or out-of-order at offset %zu.");

            size_t end_pos = temp_offset.offset + offset_len;
            if (end_pos > current_pos) {
                current_pos = (end_pos > buff_size) ? buff_size : end_pos;
            }
            continue;
        }

        size_t bytes_to_write = temp_offset.offset - current_pos;
        printf("bytes to write: %zu, current pos: %zu\n", bytes_to_write, current_pos);
        if (bytes_to_write > 0) {
            printf("buff to write: %c\n", buffer[current_pos]);
            size_t written = fwrite(&buffer[current_pos], sizeof(unsigned char), bytes_to_write, output_file);
            if (written != bytes_to_write) {
                fprintf(stderr, "Error writing segment before offset %zu\n", temp_offset.offset);
                perror("fwrite error details");
                fclose(output_file);
                exit(1);
            }
            total_bytes += written;
        }

        current_pos = temp_offset.offset + offset_len;
        if (current_pos > buff_size) {
            current_pos = buff_size;
        }
        printf("Skipping %zu bytes from offset %zu. Next write starts at %zu\n",
            offset_len, temp_offset.offset, current_pos);
    }

    if (current_pos < buff_size) {
        size_t bytes_to_write = buff_size - current_pos;
        printf("bytes to write: %zu, current pos: %zu\n", bytes_to_write, current_pos);
        size_t written = fwrite(&buffer[current_pos], sizeof(unsigned char), bytes_to_write, output_file);
        if (written != bytes_to_write) {
            fprintf(stderr, "Error writing final segment\n");
            perror("fwrite error details");
            fclose(output_file);
            exit(1);
        }
        total_bytes += written;
    }

    printf("Successfully wrote a total of %zu bytes to '%s'.\n", total_bytes, filename);

    if (fclose(output_file) != 0) {
        perror("Error closing file");
    }
}

int is_valid_algorithm(const char *algo) {
    if (strcmp(algo, "rsa") == 0 ||
        strcmp(algo, "aes") == 0 ||
        strcmp(algo, "twofish") == 0 ||
        strcmp(algo, "serpent") == 0) {
        return 1;
    }
    return 0;
}

void print_usage(const char *prog_name) {
     fprintf(stderr, "Usage: %s [-a <algorithm>] [-p <parsed_filepath>] [other_filepaths...]\n", prog_name);
     fprintf(stderr, "Valid algorithms: rsa, aes, twofish, serpent\n");
}

OffsetPair* parse_rsa_twofish_serpent(const char *parsed_filepath) {
    FILE *parsed_file;
    char line_buffer[MAX_BUFF_SIZE];
    int line_number = 0;

    if (!(parsed_file = fopen(parsed_filepath, "r"))) {
        perror("Error opening offset file");
        exit(1);
    }

    OffsetPair *data_offset = NULL;
    data_count = 0;
    size_t data_capacity = 0;


    while (fgets(line_buffer, sizeof(line_buffer), parsed_file) != NULL) {
        line_number++;
        char *endptr_offset;
        unsigned long long offset;

        line_buffer[strcspn(line_buffer, "\r\n")] = 0;

        errno = 0;
        offset = strtoull(line_buffer, &endptr_offset, 16);

         if (errno != 0) {
             perror("Warning: Error parsing offset on line");
             fprintf(stderr, "\t\tLine %d: offset_part='%s'\n", line_number, line_buffer);
             continue;
        }
       if (*endptr_offset != '\0') {
             fprintf(stderr, "Warning: Invalid characters found while parsing offset on line %d: offset_part='%s'\n", line_number, line_buffer);
             continue;
        }

        if (data_count >= data_capacity) {
            size_t new_capacity = (data_capacity == 0) ? INITIAL_CAPACITY : data_capacity * 2;
            OffsetPair *temp_offset = realloc(data_offset, new_capacity * sizeof(OffsetPair));

            if (temp_offset == NULL) {
                perror("Error during reallocating memory");
                free(data_offset);
                fclose(parsed_file);
                exit(1);
            }

            data_offset = temp_offset;
            data_capacity = new_capacity;
        }
        data_offset[data_count].key = 0;
        data_offset[data_count].offset = offset;
        data_count++;

        printf("  Line %d: Key Size = %ld, Offset = %llx\n", line_number, data_offset[data_count-1].key, data_offset[data_count-1].offset);
    }

    if (ferror(parsed_file)) {
        perror("Error reading from file");
    }

    fclose(parsed_file);
    printf("Finished parsing.\n");
    return data_offset;
}

OffsetPair* parse_aes(const char *parsed_filepath) {
    FILE *parsed_file;
    char line_buffer[MAX_BUFF_SIZE];
    int line_number = 0;

    if (!(parsed_file = fopen(parsed_filepath, "r"))) {
        perror("Error opening offset file");
        exit(1);
    }

    OffsetPair *data_offset = NULL;
    data_count = 0;
    size_t data_capacity = 0;


    while (fgets(line_buffer, sizeof(line_buffer), parsed_file) != NULL) {
        line_number++;
        char *comma_pos;
        char *offset_str;
        char *endptr_size, *endptr_offset;
        long key_size_long;
        unsigned long long offset;

        line_buffer[strcspn(line_buffer, "\r\n")] = 0;

        comma_pos = strchr(line_buffer, ',');
        if (comma_pos == NULL) {
            fprintf(stderr, "Warning: Skipping line %d: No comma found: '%s'\n", line_number, line_buffer);
            continue;
        }

        *comma_pos = '\0';
        errno = 0;
        key_size_long = strtol(line_buffer, &endptr_size, 10);

        if (errno != 0) {
             perror("Warning: Error parsing key size on line");
             fprintf(stderr, "\t\tLine %d: '%s'\n", line_number, line_buffer);
             *comma_pos = ',';
             continue;
        }
        if (*endptr_size != '\0') {
             fprintf(stderr, "Warning: Invalid characters found while parsing key size on line %d: '%s'\n", line_number, line_buffer);
             *comma_pos = ',';
             continue;
        }
        if (key_size_long != 128 && key_size_long != 256) {
             fprintf(stderr, "Warning: Unexpected key size %ld on line %d: '%s'\n", key_size_long, line_number, line_buffer);
             continue;
        }


        offset_str = comma_pos + 1;
        errno = 0;
        offset = strtoull(offset_str, &endptr_offset, 16);

         if (errno != 0) {
             perror("Warning: Error parsing offset on line");
             fprintf(stderr, "\t\tLine %d: size=%ld, offset_part='%s'\n", line_number, key_size_long, offset_str);
             *comma_pos = ',';
             continue;
        }
       if (*endptr_offset != '\0') {
             fprintf(stderr, "Warning: Invalid characters found while parsing offset on line %d: size=%ld, offset_part='%s'\n", line_number, key_size_long, offset_str);
             *comma_pos = ',';
             continue;
        }

        if (data_count >= data_capacity) {
            size_t new_capacity = (data_capacity == 0) ? INITIAL_CAPACITY : data_capacity * 2;
            OffsetPair *temp_offset = realloc(data_offset, new_capacity * sizeof(OffsetPair));

            if (temp_offset == NULL) {
                perror("Error during reallocating memory");
                free(data_offset);
                fclose(parsed_file);
                exit(1);
            }

            data_offset = temp_offset;
            data_capacity = new_capacity;
        }
        data_offset[data_count].key = (int) key_size_long;
        data_offset[data_count].offset = offset;
        data_count++;

        printf("  Line %d: Key Size = %ld, Offset = %llx\n", line_number, data_offset[data_count-1].key, data_offset[data_count-1].offset);
    }

    if (ferror(parsed_file)) {
        perror("Error reading from file");
    }

    fclose(parsed_file);
    printf("Finished parsing.\n");
    return data_offset;
}

int main(int argc, char *argv[]) {
    int opt;
    const char *algorithm = NULL;
    const char *parsed_filepath = NULL;
    char *mem_filepath = NULL;

    while ((opt = getopt(argc, argv, "a:p:")) != -1) {
        switch (opt) {
            case 'a':
                if (is_valid_algorithm(optarg)) {
                    algorithm = optarg;
                } else {
                    fprintf(stderr, "Error: Invalid algorithm specified for -a: %s\n", optarg);
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                break;
            case 'p':
                parsed_filepath = optarg;
                break;
            case '?':
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    printf("Configuration:\n");
    printf("  Algorithm (-a): %s\n", algorithm ? algorithm : "none");
    printf("  Parsed Filepath (-p): %s\n", parsed_filepath ? parsed_filepath : "none");

    FILE *stream;
    unsigned char *buffer;

    printf("  Other Filepaths:\n");
    if (optind < argc) {
        for (int i = optind; i < argc; ++i) {
            mem_filepath = argv[i];
        }
    }

    printf("    - %s\n", mem_filepath);
    stream = open_file(mem_filepath, "rb");
    buffer = read_file(stream);

    OffsetPair *data_offset = NULL;
    if (strcmp(algorithm, "rsa") == 0) {
        data_offset = parse_rsa_twofish_serpent(parsed_filepath);
        save_file("./rsa_memdump.mem", buffer, data_offset, RSA_LEN);
    } else if (strcmp(algorithm, "aes") == 0) {
        data_offset = parse_aes(parsed_filepath);
        save_file("./aes_memdump.mem", buffer, data_offset, 0);
    } else if (strcmp(algorithm, "twofish") == 0) {
        data_offset = parse_rsa_twofish_serpent(parsed_filepath);
        save_file("./twofish_memdump.mem", buffer, data_offset, TWOFISH_256_LEN);
    } else if (strcmp(algorithm, "serpent") == 0) {
        data_offset = parse_rsa_twofish_serpent(parsed_filepath);
        save_file("./serpent_memdump.mem", buffer, data_offset, SERPENT_256_LEN);
    }
}
