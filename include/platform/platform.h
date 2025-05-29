/**
 * @file platform.h
 * @brief Platform abstraction layer
 *
 * This module provides platform-independent interfaces for system
 * functionality like memory management, threading, network I/O, etc.
 */

#ifndef PORTABLE_SSL_PLATFORM_H
#define PORTABLE_SSL_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform detection */
#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS
#elif defined(__APPLE__)
    #define PLATFORM_APPLE
#elif defined(__linux__)
    #define PLATFORM_LINUX
#else
    #define PLATFORM_UNKNOWN
#endif

/* Memory management */
void* platform_malloc(size_t size);
void* platform_calloc(size_t nmemb, size_t size);
void* platform_realloc(void* ptr, size_t size);
void platform_free(void* ptr);

/* Threading primitives */
typedef struct platform_mutex_st* platform_mutex_t;
typedef struct platform_thread_st* platform_thread_t;

platform_mutex_t platform_mutex_new(void);
void platform_mutex_free(platform_mutex_t mutex);
int platform_mutex_lock(platform_mutex_t mutex);
int platform_mutex_unlock(platform_mutex_t mutex);

platform_thread_t platform_thread_new(void (*func)(void*), void* arg);
int platform_thread_join(platform_thread_t thread);
void platform_thread_free(platform_thread_t thread);

/* Network I/O */
typedef struct platform_socket_st* platform_socket_t;

platform_socket_t platform_socket_new(void);
void platform_socket_free(platform_socket_t sock);
int platform_socket_connect(platform_socket_t sock, const char* host, uint16_t port);
int platform_socket_bind(platform_socket_t sock, const char* host, uint16_t port);
int platform_socket_listen(platform_socket_t sock, int backlog);
platform_socket_t platform_socket_accept(platform_socket_t sock);
int platform_socket_read(platform_socket_t sock, uint8_t* buf, size_t len);
int platform_socket_write(platform_socket_t sock, const uint8_t* buf, size_t len);
int platform_socket_close(platform_socket_t sock);

/* Time functions */
uint64_t platform_time_ms(void);
void platform_sleep_ms(unsigned int ms);

/* Random number generation */
int platform_random_bytes(uint8_t* buf, size_t len);

/* Initialization and cleanup */
int platform_init(void);
void platform_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* PORTABLE_SSL_PLATFORM_H */