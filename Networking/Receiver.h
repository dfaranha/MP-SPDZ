/*
 * Receiver.h
 *
 */

#ifndef NETWORKING_RECEIVER_H_
#define NETWORKING_RECEIVER_H_

#include <pthread.h>

#include "Tools/octetStream.h"
#include "Tools/WaitQueue.h"
#include "Tools/time-func.h"

class CommunicationThread
{
    int other;

protected:
    CommunicationThread(int other);
    virtual ~CommunicationThread() {}

    void run();
    virtual void run_with_error() = 0;
    virtual void fail() = 0;
};

template<class T>
class Receiver : CommunicationThread
{
    T socket;
    WaitQueue<octetStream*> in;
    WaitQueue<octetStream*> out;
    pthread_t thread;

    static void* run_thread(void* receiver);

    // prevent copying
    Receiver(const Receiver& other);

    void start();
    void stop();
    void run_with_error();
    void fail();

public:
    Timer timer;

    Receiver(T socket, int other);
    ~Receiver();

    T get_socket()
    {
        return socket;
    }

    void request(octetStream& os);
    void wait(octetStream& os);
    /* karuta-voting M2: 1 if os was received by the deadline, 0 if not (the
     * request stays pending: os must outlive the thread), -1 if the
     * connection failed */
    int wait_until(octetStream& os, const timespec& deadline);
};

#endif /* NETWORKING_RECEIVER_H_ */
