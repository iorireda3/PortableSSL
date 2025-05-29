/**
 * @file platform.c
 * @brief Implementation of platform abstraction layer
 */

#include "platform/platform.h"

#ifdef PLATFORM_WINDOWS
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <time.h>
#endif

#ifdef PLATFORM_WINDOWS
    static int wsa_initialized = 0;
#endif

/* Initialize platform */
int platform_init(void) {
#ifdef PLATFORM_WINDOWS
    WSADATA wsa_data;
    if (!wsa_initialized) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            return -1;
        }
        wsa_initialized = 1;
    }
#endif
    return 0;
}

/* Clean up platform */
void platform_cleanup(void) {
#ifdef PLATFORM_WINDOWS
    if (wsa_initialized) {
        WSACleanup();
        wsa_initialized = 0;
    }
#endif
}

/* Memory management functions */
void* platform_malloc(size_t size) {
#ifdef PLATFORM_WINDOWS
    return HeapAlloc(GetProcessHeap(), 0, size);
#else
    return malloc(size);
#endif
}

void* platform_calloc(size_t nmemb, size_t size) {
#ifdef PLATFORM_WINDOWS
    void* ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nmemb * size);
    return ptr;
#else
    return calloc(nmemb, size);
#endif
}

void* platform_realloc(void* ptr, size_t size) {
#ifdef PLATFORM_WINDOWS
    if (ptr == NULL) {
        return HeapAlloc(GetProcessHeap(), 0, size);
    }
    return HeapReAlloc(GetProcessHeap(), 0, ptr, size);
#else
    return realloc(ptr, size);
#endif
}

void platform_free(void* ptr) {
    if (ptr) {
#ifdef PLATFORM_WINDOWS
        HeapFree(GetProcessHeap(), 0, ptr);
#else
        free(ptr);
#endif
    }
}

/* Thread and mutex implementation */
#ifdef PLATFORM_WINDOWS
struct platform_mutex_st {
    CRITICAL_SECTION cs;
};

struct platform_thread_st {
    HANDLE thread;
    DWORD thread_id;
    void (*func)(void*);
    void* arg;
};
#else
struct platform_mutex_st {
    pthread_mutex_t mutex;
};

struct platform_thread_st {
    pthread_t thread;
    void (*func)(void*);
    void* arg;
};
#endif

#ifdef PLATFORM_WINDOWS
/* Windows thread callback wrapper */
static DWORD WINAPI thread_func_wrapper(LPVOID arg) {
    platform_thread_t thread = (platform_thread_t)arg;
    thread->func(thread->arg);
    return 0;
}
#else
/* POSIX thread callback wrapper */
static void* thread_func_wrapper(void* arg) {
    platform_thread_t thread = (platform_thread_t)arg;
    thread->func(thread->arg);
    return NULL;
}
#endif

platform_mutex_t platform_mutex_new(void) {
    platform_mutex_t mutex = (platform_mutex_t)platform_malloc(sizeof(struct platform_mutex_st));
    if (!mutex) {
        return NULL;
    }
    
#ifdef PLATFORM_WINDOWS
    InitializeCriticalSection(&mutex->cs);
#else
    pthread_mutex_init(&mutex->mutex, NULL);
#endif
    
    return mutex;
}

void platform_mutex_free(platform_mutex_t mutex) {
    if (mutex) {
#ifdef PLATFORM_WINDOWS
        DeleteCriticalSection(&mutex->cs);
#else
        pthread_mutex_destroy(&mutex->mutex);
#endif
        platform_free(mutex);
    }
}

int platform_mutex_lock(platform_mutex_t mutex) {
    if (!mutex) {
        return -1;
    }
    
#ifdef PLATFORM_WINDOWS
    EnterCriticalSection(&mutex->cs);
#else
    if (pthread_mutex_lock(&mutex->mutex) != 0) {
        return -1;
    }
#endif
    
    return 0;
}

int platform_mutex_unlock(platform_mutex_t mutex) {
    if (!mutex) {
        return -1;
    }
    
#ifdef PLATFORM_WINDOWS
    LeaveCriticalSection(&mutex->cs);
#else
    if (pthread_mutex_unlock(&mutex->mutex) != 0) {
        return -1;
    }
#endif
    
    return 0;
}

platform_thread_t platform_thread_new(void (*func)(void*), void* arg) {
    platform_thread_t thread = (platform_thread_t)platform_malloc(sizeof(struct platform_thread_st));
    if (!thread) {
        return NULL;
    }
    
    thread->func = func;
    thread->arg = arg;
    
#ifdef PLATFORM_WINDOWS
    thread->thread = CreateThread(NULL, 0, thread_func_wrapper, thread, 0, &thread->thread_id);
    if (thread->thread == NULL) {
        platform_free(thread);
        return NULL;
    }
#else
    if (pthread_create(&thread->thread, NULL, thread_func_wrapper, thread) != 0) {
        platform_free(thread);
        return NULL;
    }
#endif
    
    return thread;
}

int platform_thread_join(platform_thread_t thread) {
    if (!thread) {
        return -1;
    }
    
#ifdef PLATFORM_WINDOWS
    if (WaitForSingleObject(thread->thread, INFINITE) != WAIT_OBJECT_0) {
        return -1;
    }
#else
    if (pthread_join(thread->thread, NULL) != 0) {
        return -1;
    }
#endif
    
    return 0;
}

void platform_thread_free(platform_thread_t thread) {
    if (thread) {
#ifdef PLATFORM_WINDOWS
        CloseHandle(thread->thread);
#endif
        platform_free(thread);
    }
}

/* Socket implementation */
struct platform_socket_st {
#ifdef PLATFORM_WINDOWS
    SOCKET sock;
#else
    int sock;
#endif
};

platform_socket_t platform_socket_new(void) {
    platform_socket_t sock = (platform_socket_t)platform_malloc(sizeof(struct platform_socket_st));
    if (!sock) {
        return NULL;
    }
    
#ifdef PLATFORM_WINDOWS
    sock->sock = INVALID_SOCKET;
#else
    sock->sock = -1;
#endif
    
    return sock;
}

void platform_socket_free(platform_socket_t sock) {
    if (sock) {
        platform_socket_close(sock);
        platform_free(sock);
    }
}

/* Time functions */
uint64_t platform_time_ms(void) {
#ifdef PLATFORM_WINDOWS
    FILETIME ft;
    ULARGE_INTEGER li;
    
    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    
    /* Convert from 100ns intervals to milliseconds */
    return (li.QuadPart - 116444736000000000ULL) / 10000;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

void platform_sleep_ms(unsigned int ms) {
#ifdef PLATFORM_WINDOWS
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
#endif
}

/* Random number generation */
int platform_random_bytes(uint8_t* buf, size_t len) {
    /* This is a simplified implementation */
    /* In a real implementation, we would use platform-specific secure random sources */
#ifdef PLATFORM_WINDOWS
    HCRYPTPROV hCryptProv = 0;
    
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    
    if (!CryptGenRandom(hCryptProv, (DWORD)len, buf)) {
        CryptReleaseContext(hCryptProv, 0);
        return -1;
    }
    
    CryptReleaseContext(hCryptProv, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    size_t bytes_read = 0;
    while (bytes_read < len) {
        ssize_t ret = read(fd, buf + bytes_read, len - bytes_read);
        if (ret <= 0) {
            close(fd);
            return -1;
        }
        bytes_read += ret;
    }
    
    close(fd);
#endif
    
    return 0;
}