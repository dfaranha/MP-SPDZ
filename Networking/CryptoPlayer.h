/*
 * CryptoPlayer.h
 *
 */

#ifndef NETWORKING_CRYPTOPLAYER_H_
#define NETWORKING_CRYPTOPLAYER_H_

#include "ssl_sockets.h"
#include "Networking/Player.h"

#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>

/**
 * Encrypted multi-party communication.
 * Uses OpenSSL and certificates issued to "P<player_no>".
 * Sending and receiving is done in separate threads to allow
 * for bidirectional communication.
 */
class CryptoPlayer : public MultiPlayer<ssl_socket*>
{
    ssl_ctx ctx;
    ssl_service io_service;

    vector<ssl_socket*> other_sockets;

    vector<Sender<ssl_socket*>*> senders;
    vector<Receiver<ssl_socket*>*> receivers;

    void connect(int other, vector<int>* plaintext_sockets);

    /* karuta-voting M3: peers absent at setup (PlainPlayer::setup_timeout) */
    vector<char> absent;

public:
    bool is_absent(int other) const
    {
        return absent.at(other);
    }

    /**
     * Start a new set of encrypted connections.
     * @param Nms network setup
     * @param id unique identifier
     */
    CryptoPlayer(const Names& Nms, const string& id);
    // legacy interface
    CryptoPlayer(const Names& Nms, int id_base = 0);
    ~CryptoPlayer();

    bool is_encrypted() { return true; }

    void send_to_no_stats(int other, const octetStream& o) const;
    void receive_player_no_stats(int other, octetStream& o) const;

    size_t send_no_stats(int player, const PlayerBuffer& buffer,
            bool block) const;
    size_t recv_no_stats(int player, const PlayerBuffer& buffer,
            bool block) const;

    void exchange_no_stats(int other, const octetStream& to_send,
        octetStream& to_receive) const;

    void pass_around_no_stats(const octetStream& to_send, octetStream& to_receive,
        int offset) const;

    /* karuta-voting M2: send to_send[j] to and receive to_receive[j] from each
     * j with live[j], waiting until `timeout` seconds from the call. A peer
     * whose send or receive is not done by then, or whose connection fails,
     * gets live[j] = 0; its two octetStreams are still referenced by the
     * communication threads and must never be freed or used again. */
    void send_receive_live(const vector<octetStream*>& to_send,
            const vector<octetStream*>& to_receive, vector<char>& live,
            double timeout) const;

    void send_receive_all_no_stats(const vector<vector<bool>>& channels,
            const vector<octetStream>& to_send,
            vector<octetStream>& to_receive) const;

    void partial_broadcast_no_stats(const vector<bool>& my_senders,
            const vector<bool>& my_receivers, vector<octetStream>& os) const;

    void Broadcast_Receive_no_stats(vector<octetStream>& os) const;

    Player* fresh_fork(string suffix);
};

#endif /* NETWORKING_CRYPTOPLAYER_H_ */
