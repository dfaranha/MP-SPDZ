/*
 * CryptoPlayer.cpp
 *
 */

#include "CryptoPlayer.h"
#include "Math/Setup.h"
#include "Tools/Bundle.h"

void check_ssl_file(string filename)
{
    if (not ifstream(filename))
        exit_error("Cannot access " + filename
                        + ". Have you set up SSL?\n"
                        "You can use `Scripts/setup-ssl.sh <nparties>`.");
}

void ssl_error(string side, string other, string me, exception& e)
{
    cerr << side << "-side handshake with " << other
            << " failed. Make sure both sides "
            << " have the necessary certificate (" << SSL_DIR << me
            << ".pem in the default configuration on their side and "
            << SSL_DIR << other << ".pem on ours),"
            << " and run `c_rehash <directory>` on its location." << endl
            << "The certificates should be the same on every host. "
            << "Also make sure that it's still valid. Certificates generated "
            << "with `Scripts/setup-ssl.sh` expire after a month." << endl;
    cerr << "See also "
            "https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html"
            "#handshake-failures" << endl;

    string ids[2];
    ids[side == "Client"] = other;
    ids[side != "Client"] = me;
    cerr << "Signature (should match the other side): ";
    for (int i = 0; i < 2; i++)
    {
        auto filename = SSL_DIR + ids[i] + ".pem";
        ifstream cert(filename);
        stringstream buffer;
        buffer << cert.rdbuf();
        if (buffer.str().empty())
            cerr << "<'" << filename << "' not found>";
        else
            cerr << octetStream(buffer.str()).hash();
        if (i == 0)
            cerr << "/";
    }
    cerr << endl;
    cerr << "SSL error: " << e.what() << endl;
    exit(1);
}

CryptoPlayer::CryptoPlayer(const Names& Nms, const string& id_base) :
        MultiPlayer<ssl_socket*>(Nms, id_base),
        ctx("P" + to_string(my_num()))
{
    sockets.resize(num_players());
    other_sockets.resize(num_players());
    senders.resize(num_players());
    receivers.resize(num_players());

    vector<int> plaintext_sockets[2];

    for (int i = 0; i < 2; i++)
    {
        PlainPlayer player(Nms, id_base + (i ? "recv" : ""));
        plaintext_sockets[i] = player.sockets;
        close_client_socket(player.socket(my_num()));
        player.sockets.clear();
    }

    /* karuta-voting M3: no TLS and no communication threads for a peer that
     * is absent on either plaintext connection */
    absent.assign(num_players(), 0);
    for (int i = 0; i < num_players(); i++)
    {
        if (i == my_num())
            continue;
        absent[i] = plaintext_sockets[0][i] < 0 or plaintext_sockets[1][i] < 0;
        if (absent[i])
            for (int j = 0; j < 2; j++)
                if (plaintext_sockets[j][i] >= 0)
                    close_client_socket(plaintext_sockets[j][i]);
    }

    for (auto& other : balanced_others())
        if (not absent[other])
        {
            if (PlainPlayer::setup_timeout <= 0)
            {
                connect(other, plaintext_sockets);
                continue;
            }
            /* karuta-voting M3: a failed handshake makes the peer absent */
            ssl_socket::tolerant = true;
            try
            {
                connect(other, plaintext_sockets);
            }
            catch (exception& e)
            {
                cerr << "P" << my_num() << ": TLS setup with P" << other
                        << " failed (" << e.what() << "); treating it as absent"
                        << endl;
                delete sockets[other];
                sockets[other] = 0;
                absent[other] = 1;
            }
            ssl_socket::tolerant = false;
        }

    for (int i = 0; i < num_players(); i++)
    {
        if (i == my_num() or absent[i])
        {
            sockets[i] = 0;
            senders[i] = 0;
            other_sockets[i] = 0;
            receivers[i] = 0;
            continue;
        }

        senders[i] = new Sender<ssl_socket*>(
                i < my_num() ? sockets[i] : other_sockets[i], i);
        receivers[i] = new Receiver<ssl_socket*>(
                i < my_num() ? other_sockets[i] : sockets[i], i);
    }
}

void CryptoPlayer::connect(int i, vector<int>* plaintext_sockets)
{
    sockets[i] = new ssl_socket(io_service, ctx, plaintext_sockets[0][i],
            "P" + to_string(i), "P" + to_string(my_num()), i < my_num());
    other_sockets[i] = new ssl_socket(io_service, ctx, plaintext_sockets[1][i],
            "P" + to_string(i), "P" + to_string(my_num()), i < my_num());

}

CryptoPlayer::CryptoPlayer(const Names& Nms, int id_base) :
        CryptoPlayer(Nms, to_string(id_base))
{
}

CryptoPlayer::~CryptoPlayer()
{
    for (int i = 0; i < num_players(); i++)
    {
        delete sockets[i];
        delete other_sockets[i];
        delete senders[i];
        delete receivers[i];
    }
}

void CryptoPlayer::send_to_no_stats(int other, const octetStream& o) const
{
    assert(other != my_num());
    senders[other]->request(o);
    senders[other]->wait(o);
}

void CryptoPlayer::receive_player_no_stats(int other, octetStream& o) const
{
    assert(other != my_num());
    receivers[other]->request(o);
    receivers[other]->wait(o);
}

size_t CryptoPlayer::send_no_stats(int player, const PlayerBuffer& buffer,
        bool block) const
{
    assert(player != my_num());
    auto socket = senders.at(player)->get_socket();
    if (block)
    {
        send(socket, buffer.data, buffer.size);
        return buffer.size;
    }
    else
        return send_non_blocking(socket, buffer.data, buffer.size);
}

size_t CryptoPlayer::recv_no_stats(int player, const PlayerBuffer& buffer,
        bool block) const
{
    assert(player != my_num());
    auto socket = receivers.at(player)->get_socket();
    if (block)
    {
        receive(socket, buffer.data, buffer.size);
        return buffer.size;
    }
    else
        return receive_non_blocking(socket, buffer.data, buffer.size);
}

void CryptoPlayer::exchange_no_stats(int other, const octetStream& to_send,
        octetStream& to_receive) const
{
    assert(other != my_num());
    if (&to_send == &to_receive)
    {
        MultiPlayer<ssl_socket*>::exchange_no_stats(other, to_send, to_receive);
    }
    else
    {
        senders[other]->request(to_send);
        receivers[other]->request(to_receive);
        senders[other]->wait(to_send);
        receivers[other]->wait(to_receive);
    }
}

void CryptoPlayer::pass_around_no_stats(const octetStream& to_send,
        octetStream& to_receive, int offset) const
{
    assert(get_player(offset) != my_num());
    if (&to_send == &to_receive)
    {
        MultiPlayer<ssl_socket*>::pass_around_no_stats(to_send, to_receive, offset);
    }
    else
    {
#ifdef TIME_ROUNDS
        Timer recv_timer;
        TimeScope ts(recv_timer);
#endif
        senders[get_player(offset)]->request(to_send);
        receivers[get_player(-offset)]->request(to_receive);
        senders[get_player(offset)]->wait(to_send);
        receivers[get_player(-offset)]->wait(to_receive);
#ifdef TIME_ROUNDS
        cout << "Exchange time: " << recv_timer.elapsed() << " seconds to receive "
            << 1e-3 * to_receive.get_length() << " KB" << endl;
#endif
    }
}

void CryptoPlayer::send_receive_all_no_stats(const vector<vector<bool>>& channels,
        const vector<octetStream>& to_send,
        vector<octetStream>& to_receive) const
{
    to_receive.resize(num_players());
    bool global = channels.empty();
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = global or channels[other][my_num()];
        if (global or channels[my_num()][other])
            this->senders[other]->request(to_send[other]);
        if (receive)
            this->receivers[other]->request(to_receive[other]);
    }
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = global or channels[other][my_num()];
        if (global or channels[my_num()][other])
            this->senders[other]->wait(to_send[other]);
        if (receive)
            this->receivers[other]->wait(to_receive[other]);
    }
}

void CryptoPlayer::send_receive_live(const vector<octetStream*>& to_send,
        const vector<octetStream*>& to_receive, vector<char>& live,
        double timeout) const
{
    timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    long ns = deadline.tv_nsec + long((timeout - long(timeout)) * 1e9);
    deadline.tv_sec += long(timeout) + ns / 1000000000L;
    deadline.tv_nsec = ns % 1000000000L;
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        if (not live[other])
            continue;
        senders[other]->request(*to_send[other]);
        receivers[other]->request(*to_receive[other]);
        sent += to_send[other]->get_length();
    }
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        if (not live[other])
            continue;
        if (senders[other]->wait_until(*to_send[other], deadline) != 1
                or receivers[other]->wait_until(*to_receive[other], deadline) != 1)
            live[other] = 0;
    }
}

void CryptoPlayer::partial_broadcast_no_stats(const vector<bool>& my_senders,
        const vector<bool>& my_receivers,
        vector<octetStream>& os) const
{
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = my_senders.at(other);
        if (my_receivers.at(other))
        {
            this->senders[other]->request(os[my_num()]);
            sent += os[my_num()].get_length();
        }
        if (receive)
            this->receivers[other]->request(os[other]);
    }
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = my_senders[other];
        if (my_receivers[other])
            this->senders[other]->wait(os[my_num()]);
        if (receive)
            this->receivers[other]->wait(os[other]);
    }
}

void CryptoPlayer::Broadcast_Receive_no_stats(vector<octetStream>& os) const
{
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        this->senders[other]->request(os[my_num()]);
        receivers[other]->request(os[other]);
    }

    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        this->senders[other]->wait(os[my_num()]);
        receivers[other]->wait(os[other]);
    }
}

Player* CryptoPlayer::fresh_fork(string suffix)
{
    return new CryptoPlayer(N, get_id() + "-" + suffix);
}
