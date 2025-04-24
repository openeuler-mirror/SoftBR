#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#define NUM_THREADS 4
#define ARRAY_SIZE 1000000

typedef struct {
    pid_t pid;
    int pipes[2];
} fork_pthread;

typedef fork_pthread* pthread_t;
typedef void pthread_attr_t;

void setalarm(int duration) {
    alarm(duration);
}

void* xmalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static int pthread_create(pthread_t* thread, pthread_attr_t* attr, void* (*start_routine)(void*), void* arg) {
    fork_pthread* th = NULL;
    void* ret = NULL;

    th = (fork_pthread*)xmalloc(sizeof(fork_pthread));
    if (pipe(th->pipes) < 0) {
        free(th);
        return errno;
    }

    th->pid = fork();
    if (th->pid == -1) {
        free(th);
        return errno;
    }
    if (th->pid != 0) {
        close(th->pipes[1]);
        *thread = th;
        return 0;
    }

    close(th->pipes[0]);

    int duration = 0; // Adjust this as necessary
    if (duration > 0)
        setalarm(duration);

    ret = start_routine(arg);
    write(th->pipes[1], &ret, sizeof(void*));
    close(th->pipes[1]);
    free(th);
    exit(0);
}

static int pthread_join(pthread_t thread, void** retval) {
    int status;
    waitpid(thread->pid, &status, 0);
    if (retval) {
        read(thread->pipes[0], retval, sizeof(void*));
    }
    close(thread->pipes[0]);
    free(thread);
    return 0;
}

typedef struct {
    int *array;
    int start;
    int end;
    long long sum;
} thread_data_t;

void* compute_sum(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    long long sum = 0;
    for (int i = data->start; i < data->end; i++) {
        sum += data->array[i];
    }
    data->sum = sum;
    return (void*)(data->sum);
}

int main() {
    int array[ARRAY_SIZE];
    for (int i = 0; i < ARRAY_SIZE; i++) {
        array[i] = 1;  // Initialize array with 1s
    }

    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    int segment_size = ARRAY_SIZE / NUM_THREADS;

    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].array = array;
        thread_data[i].start = i * segment_size;
        thread_data[i].end = (i == NUM_THREADS - 1) ? ARRAY_SIZE : (i + 1) * segment_size;
        pthread_create(&threads[i], NULL, compute_sum, &thread_data[i]);
    }

    // Join threads and aggregate results
    long long total_sum = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        void* ret;
        pthread_join(threads[i], &ret);
        total_sum += (long long)ret;
    }

    printf("Total sum: %lld\n", total_sum);
    return 0;
}

