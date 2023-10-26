#ifndef PRE_CLIENT_H
#define PRE_CLIENT_H

#include "pre_utils.h"

// common to both Producers and Consumers
class PreCommonClient : public olc::net::client_interface<PreMsgTypes> {
public:
  OPENFHE_DEBUG_FLAG(false); // set to true to turn on OPENFHE_DEBUG()
                             // statements

  void RequestCC(void) {
    olc::net::message<PreMsgTypes> msg;
    OPENFHE_DEBUG("Client: Requesting CC");
    msg.header.id = PreMsgTypes::RequestCC;
    Send(msg);
  }

  CC RecvCC(olc::net::message<PreMsgTypes> &msg) {
    CC cc;
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("Client: read CC of " << msgSize << " bytes");
    OPENFHE_DEBUG("Client: msg.size() " << msg.size());
    OPENFHE_DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("Client istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("Client: Deserialize");
    Serial::Deserialize(cc, is, SerType::BINARY);

    OPENFHE_DEBUG("Client: Done");
    assert(is.good());
    return cc;
  }
};

// producer client methods
class PreProducerClient : public PreCommonClient {

public:
  OPENFHE_DEBUG_FLAG(false); // set to true to turn on OPENFHE_DEBUG()
                             // statements

  void SendPrivateKey(KPair &kp) {
    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("Producer: serializing secret key");
    Serial::Serialize(kp.secretKey, os, SerType::BINARY);
    OPENFHE_DEBUG("Producer: done");
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendPrivateKey;
    msg << os.str();
    OPENFHE_DEBUG("Producer: final msg.body.size " << msg.body.size());
    OPENFHE_DEBUG("Producer: final msg.size " << msg.size());
    Send(msg);
  }

  void SendCT(CT &ct) {
    OPENFHE_DEBUG("Producer: serializing CT");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(ct, os, SerType::BINARY);
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendCT;
    msg << os.str();
    OPENFHE_DEBUG("Producer: final msg.body.size " << msg.body.size());
    OPENFHE_DEBUG("Producer: final msg.size " << msg.size());
    Send(msg);
  }

  void RequestVecInt(void) {
    olc::net::message<PreMsgTypes> msg;
    OPENFHE_DEBUG("Producer: Requesting VecInt");
    msg.header.id = PreMsgTypes::RequestVecInt;
    Send(msg);
  }
  vecInt RecvVecInt(olc::net::message<PreMsgTypes> &msg) {
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("Producer: read vecInt of " << msgSize << " bytes");
    OPENFHE_DEBUG("Producer: msg.size() " << msg.size());
    OPENFHE_DEBUG("Producer: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("Producer istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("Producer: Deserialize");
    vecInt vi; // create the vector
    Serial::Deserialize(vi, is, SerType::BINARY);
    OPENFHE_DEBUG("Producer: Done");
    assert(is.good());
    return vi;
  }

  void DisconnectProducer(void) {
    olc::net::message<PreMsgTypes> msg;
    OPENFHE_DEBUG("Producer: Sending DisconnectProducer");
    msg.header.id = PreMsgTypes::DisconnectProducer;
    Send(msg);
  }
};

// consumer client methods
class PreConsumerClient : public PreCommonClient {
public:
  OPENFHE_DEBUG_FLAG(false); // set to true to turn on OPENFHE_DEBUG()
                             // statements

  void SendPublicKey(KPair &kp) {
    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("Consumer: serializing public key");
    Serial::Serialize(kp.publicKey, os, SerType::BINARY);
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendPublicKey;
    msg << os.str();
    OPENFHE_DEBUG("Consumer: final msg.body.size " << msg.body.size());
    OPENFHE_DEBUG("Consumer: final msg.size " << msg.size());
    Send(msg);
  }

  void RequestReEncryptionKey(void) {
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::RequestReEncryptionKey;
    Send(msg);
  }

  EvKey RecvReencryptionKey(olc::net::message<PreMsgTypes> &msg) {
    EvKey reencKey;
    unsigned int msgSize(msg.body.size());
    OPENFHE_DEBUG("CLIENT: read CC of " << msgSize << " bytes");
    OPENFHE_DEBUG("Client: msg.size() " << msg.size());
    OPENFHE_DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(reencKey, is, SerType::BINARY);
    return reencKey;
  }

  void RequestCT(void) {
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::RequestCT;
    Send(msg);
  }

  CT RecvCT(olc::net::message<PreMsgTypes> &msg) {
    CT ct;
    unsigned int msgSize(msg.body.size());
    OPENFHE_DEBUG("CLIENT: read CT of " << msgSize << " bytes");
    OPENFHE_DEBUG("Client: msg.size() " << msg.size());
    OPENFHE_DEBUG("Client: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("CLIENT istringstream.str.size(): " << is.str().size());
    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("CLIENT: Deserialize");
    Serial::Deserialize(ct, is, SerType::BINARY);
    return ct;
  }

  void SendVecInt(vecInt &vi) {
    OPENFHE_DEBUG("Consumer: serializing vecInt");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(vi, os, SerType::BINARY);
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendVecInt;
    msg << os.str();
    OPENFHE_DEBUG("Consumer: final msg.body.size " << msg.body.size());
    OPENFHE_DEBUG("Consumer: final msg.size " << msg.size());
    OPENFHE_DEBUG("Consumer: sending vecInt " << msg.size() << " bytes");
    Send(msg);
  }

  void DisconnectConsumer(void) {
    olc::net::message<PreMsgTypes> msg;
    OPENFHE_DEBUG("Producer: Sending DisconnectConsumer");
    msg.header.id = PreMsgTypes::DisconnectConsumer;
    Send(msg);
  }
};

#endif // PRE_CLIENT_H
