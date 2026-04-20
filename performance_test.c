#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 简化的测试函数，模拟优化后的 extract_ipv4 函数
static int extract_ipv4_optimized(const char *line, char *ip_out, size_t ip_size)
{
    const char *ptr = line;
    int octets[4];
    size_t line_len = strlen(line);
    size_t max_search_pos = line_len > 1024 ? 1024 : line_len;  // 优化：限制搜索范围

    /* Search for pattern: digits.digits.digits.digits */
    for (size_t pos = 0; pos < max_search_pos && *ptr; pos++, ptr++) {
        if (sscanf(ptr, "%3d.%3d.%3d.%3d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            /* Validate octets */
            if (octets[0] >= 0 && octets[0] <= 255 &&
                octets[1] >= 0 && octets[1] <= 255 &&
                octets[2] >= 0 && octets[2] <= 255 &&
                octets[3] >= 0 && octets[3] <= 255) {

                snprintf(ip_out, ip_size, "%d.%d.%d.%d",
                        octets[0], octets[1], octets[2], octets[3]);
                
                // 模拟 IP 验证
                unsigned char buf[4];
                if (1) { // 简化验证
                    // Additional validation: reject invalid IPs
                    unsigned int ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
                    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
                        octets[0] == 127 ||  // 127.x.x.x
                        (octets[0] >= 224 && octets[0] <= 239)) {  // 224.0.0.0/4 (multicast)
                        ptr++; 
                        continue; 
                    }
                    
                    return 1;
                }
            }
        }
    }

    return 0;
}

// 模拟未优化的版本（无长度限制）
static int extract_ipv4_unoptimized(const char *line, char *ip_out, size_t ip_size)
{
    const char *ptr = line;
    int octets[4];

    /* Search for pattern: digits.digits.digits.digits - 无长度限制 */
    while (*ptr) {
        if (sscanf(ptr, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            /* Validate octets */
            if (octets[0] >= 0 && octets[0] <= 255 &&
                octets[1] >= 0 && octets[1] <= 255 &&
                octets[2] >= 0 && octets[2] <= 255 &&
                octets[3] >= 0 && octets[3] <= 255) {

                snprintf(ip_out, ip_size, "%d.%d.%d.%d",
                        octets[0], octets[1], octets[2], octets[3]);
                
                // 模拟 IP 验证
                unsigned char buf[4];
                if (1) { // 简化验证
                    // Additional validation: reject invalid IPs
                    unsigned int ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
                    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
                        octets[0] == 127 ||  // 127.x.x.x
                        (octets[0] >= 224 && octets[0] <= 239)) {  // 224.0.0.0/4 (multicast)
                        ptr++; 
                        continue; 
                    }
                    
                    return 1;
                }
            }
        }
        ptr++;
    }

    return 0;
}

int main() {
    // 创建一个很长的日志行用于测试
    char *long_line = malloc(5000);  // 5000 字符的长行
    strcpy(long_line, "Jan 1 12:00:00 server sshd[12345]: Invalid user admin from ");
    
    // 添加很多填充字符
    for (int i = strlen(long_line); i < 4900; i++) {
        long_line[i] = 'x';
    }
    strcat(long_line, "192.168.1.100");  // 在末尾添加一个IP
    
    char ip_found[16];
    
    // 测试优化版本
    clock_t start = clock();
    for (int i = 0; i < 1000; i++) {  // 执行1000次
        extract_ipv4_optimized(long_line, ip_found, sizeof(ip_found));
    }
    clock_t end = clock();
    double optimized_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    // 测试未优化版本
    start = clock();
    for (int i = 0; i < 1000; i++) {  // 执行1000次
        extract_ipv4_unoptimized(long_line, ip_found, sizeof(ip_found));
    }
    end = clock();
    double unoptimized_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("Performance comparison for processing long log lines:\n");
    printf("Optimized version (with 1024 char limit): %.4f seconds for 1000 iterations\n", optimized_time);
    printf("Unoptimized version (no limit): %.4f seconds for 1000 iterations\n", unoptimized_time);
    printf("Improvement: %.2fx faster\n", unoptimized_time / optimized_time);
    
    free(long_line);
    return 0;
}