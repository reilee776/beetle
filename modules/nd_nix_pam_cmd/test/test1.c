#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 파일에서 첫 번째 문자열을 검색하는 함수
int exists_in_file(const char *filename, const char *key) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        // 파일이 없는 경우 -1 반환
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *delimiter = strchr(line, '|');
        if (delimiter != NULL) {
            *delimiter = '\0'; // Separate key
            if (strcmp(line, key) == 0) {
                fclose(file);
                return 1; // Key found
            }
        }
    }

    fclose(file);
    return 0; // Key not found
}

// 파일에 문자열을 추가하는 함수
int append_to_file(const char *filename, const char *data) {
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    fprintf(file, "%s\n", data);
    fclose(file);
    return 0;
}

// 메인 함수
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <field1> <field2> <field3>\n", argv[0]);
        return 1;
    }

    const char *filename = "aaa.data";
    char data[256];
    snprintf(data, sizeof(data), "%s|%s|%s", argv[1], argv[2], argv[3]);

    // Check if the file exists
    if (exists_in_file(filename, argv[1]) == -1) {
        // File does not exist, so create it and add data
        if (append_to_file(filename, data) == 0) {
            printf("File created and data added successfully: %s\n", data);
        } else {
            printf("Failed to create file and add data.\n");
        }
    } else if (exists_in_file(filename, argv[1]) == 0) {
        // File exists but key does not exist, so add data
        if (append_to_file(filename, data) == 0) {
            printf("Data added successfully: %s\n", data);
        } else {
            printf("Failed to add data.\n");
        }
    } else {
        // Key already exists in file
        printf("The entry with the first field '%s' already exists in the file.\n", argv[1]);
    }

    return 0;
}

