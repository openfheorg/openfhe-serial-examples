#ifndef PRE_SERVER_H
#define PRE_SERVER_H

#include "pre_utils.h"

// based on asio connection objects from olc_net thanks to
// David Barr, aka javidx9, ©OneLoneCoder 2019, 2020

class PreServer : public olc::net::server_interface<PreMsgTypes> {
 public:
  OPENFHE_DEBUG_FLAG(false);

  PreServer(uint16_t nPort)
      : olc::net::server_interface<PreMsgTypes>(nPort),
        m_producerPrivateKeyReceived(false),
        m_producerCTReceived(false),
        m_consumerVecIntReceived(false) {
    // initialize CC and data structures.
    OPENFHE_DEBUG("[SERVER]: Initialize CC");
    ;
    InitializeCC();
  }

 protected:
  virtual bool OnClientConnect(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client) {
    // add client to the data structures
    // AddClientToDS(client->GetID);
    std::cout << "[SERVER]: Adding client\n";
    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::ServerAccept;
    OPENFHE_DEBUG("[SERVER]: sending accept");
    client->Send(msg);
    OPENFHE_DEBUG("[SERVER]: done");
    return true;
  }

  // Called when a client appears to have disconnected
  virtual void OnClientDisconnect(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client) {
    std::cout << "Removing client [" << client->GetID() << "]\n";
    // remove client from the data structures
  }

  // Called when a message arrives
  virtual void OnMessage(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client,
      olc::net::message<PreMsgTypes>& msg) {
    switch (msg.header.id) {
      case PreMsgTypes::RequestCC:
        std::cout << "[" << client->GetID() << "]: RequestCC\n";
        SendClientCC(client);  // this queues next task
        break;
      case PreMsgTypes::SendPrivateKey:

        std::cout << "[" << client->GetID() << "]: SendPrivateKey\n";
        // receive private key from this client, store it in data structure with
        // this client as key
        RecvClientPrivateKey(client, msg);
        {
          // send acknowledgement
          olc::net::message<PreMsgTypes> ackMsg;
          ackMsg.header.id = PreMsgTypes::AckPrivateKey;
          client->Send(ackMsg);
        }
        break;

      case PreMsgTypes::SendPublicKey:

        std::cout << "[" << client->GetID() << "]: SendPublicKey\n";
        // receive the public key from this client, generate a re-encryption key
        // todo, have consumer ID producer that they want a re-encryption key
        // to.. store the reencryption key in a data structure with the producer
        // consumer as the key.
        // create a channel for the producer consumer pair.
        // send reencryption key.

        RecvClientPublicKey(client, msg);
        {
          // send acknowledgement
          olc::net::message<PreMsgTypes> ackMsg;
          ackMsg.header.id = PreMsgTypes::AckPublicKey;
          client->Send(ackMsg);
        }
        break;
      case PreMsgTypes::RequestReEncryptionKey:

        std::cout << "[" << client->GetID() << "]: RequestReEncryptionKey\n";
        m_clientID = msg.header.SubType_ID;
        SendClientReEncryptionKey(client);  // this queues next task

        break;

      case PreMsgTypes::SendCT:

        std::cout << "[" << client->GetID() << "]: SendCT\n";
        // receive ciphertext
        // store it in the producer's data structure.
        RecvClientCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<PreMsgTypes> ackMsg;
          ackMsg.header.id = PreMsgTypes::AckCT;
          client->Send(ackMsg);
        }
        break;

      case PreMsgTypes::RequestCT:
        std::cout << "[" << client->GetID() << "]: RecvCT\n";
        // find the producer for this consumer
        // send the ciphertext if it exists.
        SendClientCT(client);
        break;

      case PreMsgTypes::SendVecInt:
        std::cout << "[" << client->GetID() << "]: RecvVecInt\n";
        // receive checkvector from consumer,
        // store it in the appropriate producer's data structure
        RecvClientVecInt(client, msg);
        {
          // send acknowledgement
          olc::net::message<PreMsgTypes> ackMsg;
          ackMsg.header.id = PreMsgTypes::AckVecInt;
          client->Send(ackMsg);
        }
        break;

      case PreMsgTypes::RequestVecInt:
        std::cout << "[" << client->GetID() << "]: SendVecInt\n";
        // send the vector if it exists.
        // if it does not exist , loop until it does exist....
        SendClientVecInt(client);
        break;
        // need to handle all cases or complier complains with -Werror=switch
      default:
        std::cout << "[" << client->GetID() << "]: unprocessed message\n";
    }
  }

  void InitializeCC(void) {
    PROFILELOG("[SERVER] Initializing");
    TimeVar t;  // time benchmarking variables
    PROFILELOG("[SERVER] Generating crypto context");
    TIC(t);
    int plaintextModulus = 256;  // can encode bytes
	
	CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetScalingModSize(60);

    m_serverCC = GenCryptoContext(parameters);

	m_serverCC->Enable(PKE);
	m_serverCC->Enable(KEYSWITCH);
	m_serverCC->Enable(LEVELEDSHE);
	m_serverCC->Enable(PRE);

    PROFILELOG("[SERVER]: elapsed time " << TOC_MS(t) << "msec.");
  }

  void SendClientCC(std::shared_ptr<olc::net::connection<PreMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending cryptocontext to [" << client->GetID() << "]:");
    Serial::Serialize(m_serverCC, os, SerType::BINARY);

    olc::net::message<PreMsgTypes> msg;
    msg.header.id = PreMsgTypes::SendCC;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }
  void RecvClientPrivateKey(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client,
      olc::net::message<PreMsgTypes>& msg) {
    // receive the private key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read privatekey of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(m_producerPrivateKey, is, SerType::BINARY);
    m_producerPrivateKeyReceived = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientPublicKey(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client,
      olc::net::message<PreMsgTypes>& msg) {
    // receive the private key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read privatekey of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(m_consumerPublicKey, is, SerType::BINARY);
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }
  void SendClientReEncryptionKey(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client) {
    olc::net::message<PreMsgTypes> msg;
    // if the PrivateKey does not yet exist, send a Nack
    if (!m_producerPrivateKeyReceived) {
      std::cout << "[SERVER] sending NackReEncryptionKey to ["
                << client->GetID() << "]:\n";
      msg.header.id = PreMsgTypes::NackReEncryptionKey;
      client->Send(msg);
      return;
    }

    TimeVar t;  // time benchmarking variable
    EvKey reencryptionKey;
    PROFILELOG("[SERVER]: making Reencryption Key");
    TIC(t);
    if (m_clientID == 0) {
      reencryptionKey =
		m_serverCC->ReKeyGen(m_producerPrivateKey, m_consumerPublicKey);
    }

    PROFILELOG("[SERVER]: elapsed time " << TOC_MS(t) << "msec.");

    std::string s;
    std::ostringstream os(s);
    std::cout << "[SERVER] sending cryptocontext to [" << client->GetID()
              << "]:\n";
    Serial::Serialize(reencryptionKey, os, SerType::BINARY);

    msg.header.id = PreMsgTypes::SendReEncryptionKey;
    msg << os.str();  // push the string onto the message.
    client->Send(msg);
  }

  void RecvClientCT(std::shared_ptr<olc::net::connection<PreMsgTypes>> client,
                    olc::net::message<PreMsgTypes>& msg) {
    // receive the CT from this client,
    // and store it in the data structure with this client as key
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read CT of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(m_producerCT, is, SerType::BINARY);
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    m_producerCTReceived = true;  // ideally should be locked
  }
  void SendClientCT(std::shared_ptr<olc::net::connection<PreMsgTypes>> client) {
    olc::net::message<PreMsgTypes> msg;
    // if the PrivateKey does not yet exist, send a Nack
    if (!m_producerCTReceived) {
      std::cout << "[SERVER] sending NackCT to [" << client->GetID() << "]:\n";
      msg.header.id = PreMsgTypes::NackCT;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending CT to [" << client->GetID() << "]:");
    Serial::Serialize(m_producerCT, os, SerType::BINARY);

    msg.header.id = PreMsgTypes::SendCT;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void RecvClientVecInt(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client,
      olc::net::message<PreMsgTypes>& msg) {
    // receive the CT from this client,
    // and store it in the data structure with this client as key
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()

    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read vecInt of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");

    Serial::Deserialize(m_consumerVecInt, is, SerType::BINARY);
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    m_consumerVecIntReceived = true;  // ideally should be locked
  }
  void SendClientVecInt(
      std::shared_ptr<olc::net::connection<PreMsgTypes>> client) {
    olc::net::message<PreMsgTypes> msg;
    // if the CT does not yet exist, send a Nack
    if (!m_consumerVecIntReceived) {
      std::cout << "[SERVER] sending NackVecInt to [" << client->GetID()
                << "]:\n";
      msg.header.id = PreMsgTypes::NackVecInt;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending VecInt to [" << client->GetID() << "]:");

    msg.header.id = PreMsgTypes::SendVecInt;

    OPENFHE_DEBUG("[SERVER]: serializing vecInt");
    std::string s;
    std::ostringstream os(s);
    Serial::Serialize(m_consumerVecInt, os, SerType::BINARY);

    msg << os.str();
    OPENFHE_DEBUG("[SERVER]: final msg.body.size " << msg.body.size());
    OPENFHE_DEBUG("[SERVER]: final msg.size " << msg.size());
    OPENFHE_DEBUG("[SERVER]: sending vecInt " << msg.size() << " bytes");
    client->Send(msg);
  }

 private:
  // Server state
  CC m_serverCC;

  // a full up server would have lists of producers and consumers,
  // and their approved connections,
  // but we will only keep track of one pair in this example

  bool m_producerPrivateKeyReceived;  // if true this has been received
  PrivKey m_producerPrivateKey;

  bool m_producerCTReceived;
  CT m_producerCT;

  PubKey m_consumerPublicKey;

  bool m_consumerVecIntReceived;
  vecInt m_consumerVecInt;
  unsigned int m_clientID;
};

#endif  // PRE_SERVER_H
