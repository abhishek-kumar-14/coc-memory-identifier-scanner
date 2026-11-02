#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/uio.h> 

#define PROC_PATH "/proc"
#define MIN_GCID_LENGTH 5
#define SCID_UUID_LENGTH 39 
#define MAX_REGION_SIZE (50 * 1024 * 1024) 
#define CHUNK_SIZE (32 * 1024) 
#define MAX_PATTERN_SIZE 128 
#define G_PATTERN_ZERO_SIZE 16 
#define SCID_PATTERN_ZERO_SIZE SCID_UUID_LENGTH
#define IGNORED_SCID_PREFIX "55-9db6c" 
#define IGNORED_SCID_PREFIX_LEN (sizeof(IGNORED_SCID_PREFIX) - 1)

char g_scid_pattern[MAX_PATTERN_SIZE] = {0}; 
char g_gcid_pattern[MAX_PATTERN_SIZE] = {0}; 
unsigned long g_gcid_address = 0; 
unsigned long g_scid_address = 0; 
bool g_second_scid_found = false; 

typedef struct {
    char* data;
    size_t size;
} MemoryBlock;

void free_memory_block(MemoryBlock* block) {
    if (block) {
        free(block->data);
        free(block);
    }
}

bool is_readable_memory_region(const char* perms) {
    return strchr(perms, 'r') != NULL;
}

bool is_scid_hex_char(char c) {
    return isxdigit((unsigned char)c) != 0;
}

size_t is_valid_scid_format(const char* str, size_t buffer_remaining) {
    const size_t uuid_len = SCID_UUID_LENGTH;
    if (buffer_remaining < uuid_len) {
        return 0;
    }

    const int segments[] = {2, 8, 4, 4, 4, 12};
    size_t current_pos = 0;

    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < segments[i]; j++) {
            if (!is_scid_hex_char(str[current_pos])) {
                return 0;
            }
            current_pos++;
        }

        if (i < 5) {
            if (str[current_pos] != '-') {
                return 0;
            }
            current_pos++;
        }
    }
    
    return (current_pos == uuid_len) ? uuid_len : 0; 
}

int find_pid_by_name(const char* process_name) {
    DIR* dir;
    struct dirent* entry;
    char path[512];
    char cmdline[2048];
    int pid = -1;
    
    dir = opendir(PROC_PATH);
    if (!dir) { return -1; } 
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            bool is_pid = true;
            for (int i = 0; entry->d_name[i] != '\0'; i++) {
                if (!isdigit(entry->d_name[i])) {
                    is_pid = false;
                    break;
                }
            }
            
            if (is_pid) {
                snprintf(path, sizeof(path), "%s/%s/cmdline", PROC_PATH, entry->d_name);
                
                FILE* f = fopen(path, "r");
                if (f) {
                    size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, f);
                    if (bytes_read > 0) {
                        cmdline[bytes_read] = '\0';
                        char* exe_path = cmdline;
                        char* exe_name = strrchr(exe_path, '/');
                        if (exe_name) {
                            exe_name++;
                        } else {
                            exe_name = exe_path;
                        }
                        
                        if (strcasestr(exe_name, process_name) != NULL) {
                            pid = atoi(entry->d_name);
                            fclose(f);
                            closedir(dir);
                            return pid;
                        }
                    }
                    fclose(f);
                }
            }
        }
    }
    
    closedir(dir);
    return -1;
}

MemoryBlock* read_process_memory(int pid, unsigned long address, size_t size) {
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    
    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) { return NULL; }
    
    MemoryBlock* block = (MemoryBlock*)malloc(sizeof(MemoryBlock));
    if (!block) { close(fd); return NULL; }
    
    block->data = (char*)malloc(size);
    if (!block->data) { free(block); close(fd); return NULL; }
    
    off_t offset = lseek(fd, (off_t)address, SEEK_SET);
    if (offset == (off_t)-1 || offset != (off_t)address) {
        free_memory_block(block); close(fd); return NULL;
    }
    
    ssize_t bytes_read = read(fd, block->data, size);
    if (bytes_read <= 0) {
        free_memory_block(block); close(fd); return NULL;
    }
    
    block->size = (size_t)bytes_read;
    close(fd);
    return block;
}

ssize_t zero_out_remote_memory(pid_t pid, unsigned long remote_addr, size_t size) {
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    
    int fd = open(mem_path, O_WRONLY);
    if (fd < 0) { 
        return -1; 
    } 
    
    off_t offset = lseek(fd, (off_t)remote_addr, SEEK_SET);
    if (offset == (off_t)-1 || offset != (off_t)remote_addr) {
        close(fd);
        return -2; 
    }
    
    char zero_buffer[size];
    memset(zero_buffer, 0, size); 
    
    ssize_t bytes_written = write(fd, zero_buffer, size);
    
    close(fd);
    return bytes_written;
}

void find_all_patterns_in_buffer(const char* buffer, size_t buffer_size, unsigned long base_address) {
    size_t start = 0;
    
    if (g_gcid_pattern[0] != 0 && g_second_scid_found) {
        return; 
    }

    while (start < buffer_size) {
        
        if (!g_second_scid_found) {
            if (buffer_size - start >= SCID_UUID_LENGTH) {
                size_t scid_len = is_valid_scid_format(buffer + start, buffer_size - start);

                if (scid_len > 0) {
                    if (strncmp(buffer + start, IGNORED_SCID_PREFIX, IGNORED_SCID_PREFIX_LEN) != 0) {
                        size_t pattern_length = scid_len; 
                        if (pattern_length < MAX_PATTERN_SIZE) {
                            memcpy(g_scid_pattern, buffer + start, pattern_length);
                            g_scid_pattern[pattern_length] = '\0';
                            g_scid_address = base_address + start;
                            g_second_scid_found = true;
                        }
                    }
                    
                    start += scid_len;
                    if (g_second_scid_found) continue; 
                }
            }
        }
        
        if (g_gcid_pattern[0] == 0 && start + 2 < buffer_size && 
            buffer[start] == 'G' && buffer[start + 1] == ':') 
        {
            size_t id_start = start + 2;
            size_t end = id_start;
            int len = 0;
            
            while (end < buffer_size && isdigit((unsigned char)buffer[end])) {
                len++;
                end++;
            }
            
            if (len >= MIN_GCID_LENGTH) {
                size_t pattern_length = end - start;
                if (pattern_length < MAX_PATTERN_SIZE) {
                    memcpy(g_gcid_pattern, buffer + start, pattern_length);
                    g_gcid_pattern[pattern_length] = '\0';
                    g_gcid_address = base_address + start;
                }
                start = end;
                continue; 
            }
            
            start = id_start; 
        } else {
            start++;
        }
    }
}


void scan_process_memory(int pid) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        printf("No\n");
        printf("Not Found\n");
        return;
    }
    
    char line[512];
    unsigned long start_addr, end_addr;
    char perms[16];
    char pathname[256];
    
    while (fgets(line, sizeof(line), maps_file)) {
        if (g_gcid_pattern[0] != 0 && g_second_scid_found) break; 
        
        if (sscanf(line, "%lx-%lx %s %*s %*s %*s %[^\n]", &start_addr, &end_addr, perms, pathname) < 3) {
            pathname[0] = '\0'; 
        }

        if (is_readable_memory_region(perms) && strstr(pathname, "libc_malloc")) {
            size_t region_size = end_addr - start_addr;
            
            if (region_size > MAX_REGION_SIZE) continue; 
            
            for (unsigned long offset = 0; offset < region_size; offset += CHUNK_SIZE) {
                size_t remaining_size = region_size - offset;
                size_t chunk_size = (remaining_size > CHUNK_SIZE) ? CHUNK_SIZE : remaining_size;
                unsigned long current_addr = start_addr + offset;
                
                MemoryBlock* block = read_process_memory(pid, current_addr, chunk_size);
                
                if (block) {
                    find_all_patterns_in_buffer(block->data, block->size, current_addr);
                    free_memory_block(block);
                }
                
                if (g_gcid_pattern[0] != 0 && g_second_scid_found) break; 
            }
        }
    }
    
    fclose(maps_file);

    bool scid_flush_success = false;
    bool gcid_flush_success = false;

    // Flush SCID
    if (g_scid_pattern[0] != 0 && g_scid_address != 0) {
        ssize_t written = zero_out_remote_memory(pid, g_scid_address, SCID_PATTERN_ZERO_SIZE);
        if (written > 0) scid_flush_success = true;
    }
    
    // Flush GCID
    if (g_gcid_pattern[0] != 0 && g_gcid_address != 0) {
        ssize_t written = zero_out_remote_memory(pid, g_gcid_address, G_PATTERN_ZERO_SIZE);
        if (written > 0) gcid_flush_success = true;
    }
    
    // --- FINAL REPORTING LOGIC (New Format) ---
    
    // 1. GCID Output (Line 1)
    if (g_gcid_pattern[0] != 0 && gcid_flush_success) {
        printf("Yes (%s)\n", g_gcid_pattern);
    } else if (g_gcid_pattern[0] != 0 && !gcid_flush_success) {
        printf("Flush Failed\n");
    } else {
        printf("No\n"); 
    }
    
    // 2. SCID Output (Line 2)
    const char* scid_to_print = g_scid_pattern[0] != 0 
                                ? g_scid_pattern 
                                : "Not Found";
    
    printf("%s\n", scid_to_print);
}

int main(int argc, char* argv[]) {
    FILE *f = freopen("/data/local/tmp/platform.txt", "w", stdout);
    if (f == NULL) {
        fprintf(stderr, "[ERROR] Could not open platform.txt for writing.\n");
        return 1;
    }
    
    const char* default_target = "clashofclans";
    const char* target_process = default_target;
    
    if (argc > 1) {
        target_process = argv[1];
    }
    
    int pid = find_pid_by_name(target_process);
    
    if (pid == -1) {
        const char* possible_names[] = {
            "com.supercell.clashofclans", "clashofclans", "supercell.clashofclans",
            "coc", "HD-Player", "HD-Player.exe", "Bluestacks", "Bluestacks.exe", NULL
        };
        
        for (int i = 0; possible_names[i] != NULL; i++) {
            pid = find_pid_by_name(possible_names[i]);
            if (pid != -1) {
                target_process = possible_names[i];
                break;
            }
        }
        
        if (pid == -1) {
            printf("No\n"); 
            printf("Not Found\n");
            fclose(stdout);
            return 1;
        }
    }
    
    scan_process_memory(pid);
    
    fclose(stdout);
    
    return 0;
}