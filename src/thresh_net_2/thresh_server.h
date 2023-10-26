#ifndef THRESH_SERVER_H
#define THRESH_SERVER_H

#include "thresh_utils.h"

// based on asio connection objects from olc_net thanks to
// David Barr, aka javidx9, ©OneLoneCoder 2019, 2020

class ThreshServer : public olc::net::server_interface<ThreshMsgTypes> {
 public:
  OPENFHE_DEBUG_FLAG(false);

  ThreshServer(uint16_t nPort)
      : olc::net::server_interface<ThreshMsgTypes>(nPort),
        A_Rnd1PubKeyRecd(false),
        A_evalMultKeyRecd(false),
        B_Rnd2PublicKeyRecd(false),
        B_evalMultKeyABRecd(false),
        B_evalMultKeyBABRecd(false),
        A_evalMultFinalRecd(false) {
    // initialize CC and data structures.
    OPENFHE_DEBUG("[SERVER]: Initialize CC");
    InitializeCC();
  }

 protected:
  virtual bool OnClientConnect(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    // add client to the data structures
    // AddClientToDS(client->GetID);
    std::cout << "[SERVER]: Adding client\n";
	incrementNumClients();
    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::ServerAccept;
    OPENFHE_DEBUG("[SERVER]: sending accept");
    client->Send(msg);
    OPENFHE_DEBUG("[SERVER]: done");
    return true;
  }

  // Called when a client appears to have disconnected
  virtual void OnClientDisconnect(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::cout << "Removing client [" << client->GetID() << "]\n";
    // remove client from the data structures
  }

  // Called when a message arrives
  virtual void OnMessage(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    switch (msg.header.id) {
      case ThreshMsgTypes::RequestCC:
        std::cout << "[" << client->GetID() << "]: RequestCC\n";
        SendClientCC(client);  // this queues next task
        break;

      case ThreshMsgTypes::SendRnd1PubKey:

        std::cout << "[" << client->GetID() << "]: SendRnd1PublicKey\n";
        // receive the public key from this client, send to other client for
        // Round 2 key generation.

        RecvClientAPublicKey(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd1PubKey;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd1evalMultKey:

        std::cout << "[" << client->GetID() << "]: SendRnd1EvalMultKey\n";
        // receive the evalmult key from this client, send to other client for
        // Round 2 key generation

        RecvClientAevalMultKey(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd1evalMultKey;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd1evalSumKeys:

        std::cout << "[" << client->GetID() << "]: SendRnd1EvalSumKeys\n";
        // receive the evalsumkeys from this client,

        RecvClientAevalSumKeys(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd1evalSumKeys;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd2SharedKey:

        std::cout << "[" << client->GetID() << "]: SendRnd2SharedKey\n";
        // receive the public key from this client, this is the shared public
        // key that the plaintexts will be encrypted with.

        RecvClientBPublicKey(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd2SharedKey;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd2EvalMultAB:

        std::cout << "[" << client->GetID() << "]: SendRnd2EvalMultAB\n";
        // receive the evalmultAB key from this client, send this to other
        // client for Round 3 key generation of evalMultFinal

        RecvClientBevalMultKeyAB(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd2EvalMultAB;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd2EvalMultBAB:

        std::cout << "[" << client->GetID() << "]: SendRnd2EvalMultBAB\n";
        // receive the evalmultBAB key from this client, send this to other
        // client for Round 3 key generation of evalMultFinal

        RecvClientBevalMultKeyBAB(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd2EvalMultBAB;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd2EvalSumKeysJoin:

        std::cout << "[" << client->GetID() << "]: SendRnd2EvalSumKeysJoin\n";
        // receive the evalsumkeysjoin from this client. This is the final
        // evaluation key for vector sum

        RecvClientBevalSumKeysJoin(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd2EvalSumKeysJoin;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendRnd3EvalMultFinal:

        std::cout << "[" << client->GetID() << "]: SendRnd3EvalMultFinal\n";
        // receive the evalmultfinal key from this client, this is the final
        // evaluation key for multiplication on ciphertexts

        RecvClientAevalMultFinal(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckRnd3EvalMultFinal;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::RequestRnd1PubKey:
        std::cout << "[" << client->GetID() << "]: RequestRnd1PubKey\n";
        SendClientRnd1PubKey(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd1evalMultKey:
        std::cout << "[" << client->GetID() << "]: RequestRnd1evalMultKey\n";
        SendClientRnd1evalMultKey(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd1evalSumKeys:
        std::cout << "[" << client->GetID() << "]: RequestRnd1evalSumKeys\n";
        SendClientRnd1evalSumKeys(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd2SharedKey:
        std::cout << "[" << client->GetID() << "]: RequestRnd2SharedKey\n";
        SendClientRnd2PubKey(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd2EvalMultAB:
        std::cout << "[" << client->GetID() << "]: RequestRnd2EvalMultAB\n";
        SendClientRnd2evalMultKeyAB(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd2EvalMultBAB:
        std::cout << "[" << client->GetID() << "]: RequestRnd2EvalMultBAB\n";
        SendClientRnd2evalMultKeyBAB(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd2EvalSumKeysJoin:
        std::cout << "[" << client->GetID()
                  << "]: RequestRnd2EvalSumKeysJoin\n";
        SendClientRnd2evalSumKeysJoin(client);  // this queues next task
        break;

      case ThreshMsgTypes::RequestRnd3EvalMultFinal:
        std::cout << "[" << client->GetID() << "]: RequestRnd3evalMultFinal\n";
        SendClientRnd3evalMultFinal(client);  // this queues next task
        break;

      case ThreshMsgTypes::SendCT1:

        std::cout << "[" << client->GetID() << "]: SendCT1\n";
        // receive ciphertext
        // store it in the client's data structure.
        RecvClientCT(client, msg);
        {
          // send acknowledgement
          PROFILELOG("inside recvclientct1");
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckCT1;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendCT2:

        std::cout << "[" << client->GetID() << "]: SendCT2\n";
        // receive ciphertext
        // store it in the client's data structure.
        RecvClientCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckCT2;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendCT3:

        std::cout << "[" << client->GetID() << "]: SendCT3\n";
        // receive ciphertext
        // store it in the client's data structure.
        RecvClientCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckCT3;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::RequestAddCT:
        std::cout << "[" << client->GetID() << "]: RequestAddCT\n";
        // Compute the addition ciphertext and send it.
        SendClientAddCT(client);
        break;

      case ThreshMsgTypes::RequestMultCT:
        std::cout << "[" << client->GetID() << "]: RequestMultCT\n";
        SendClientMultCT(client);
        break;

      case ThreshMsgTypes::RequestSumCT:
        std::cout << "[" << client->GetID() << "]: RequestSumCT\n";
        SendClientSumCT(client);
        break;

      case ThreshMsgTypes::RequestDecryptLeadAdd:
        std::cout << "[" << client->GetID() << "]: RequestDecryptLeadAdd\n";
        SendClientDecryptLeadAdd(client);
        break;

      case ThreshMsgTypes::RequestDecryptLeadMult:
        std::cout << "[" << client->GetID() << "]: RequestDecryptLeadMult\n";
        SendClientDecryptLeadMult(client);
        break;

      case ThreshMsgTypes::RequestDecryptLeadSum:
        std::cout << "[" << client->GetID() << "]: RequestDecryptLeadSum\n";
        SendClientDecryptLeadSum(client);
        break;

      case ThreshMsgTypes::RequestDecryptMainAdd:
        std::cout << "[" << client->GetID() << "]: RequestDecryptMainAdd\n";
        SendClientDecryptMainAdd(client);
        break;

      case ThreshMsgTypes::RequestDecryptMainMult:
        std::cout << "[" << client->GetID() << "]: RequestDecryptMainMult\n";
        SendClientDecryptMainMult(client);
        break;

      case ThreshMsgTypes::RequestDecryptMainSum:
        std::cout << "[" << client->GetID() << "]: RequestDecryptMainSum\n";
        SendClientDecryptMainSum(client);
        break;

      case ThreshMsgTypes::SendDecryptPartialMainAdd:

        std::cout << "[" << client->GetID() << "]: SendDecryptPartialMainAdd\n";
        // receive ciphertext
        // store it in the ClientB's data structure.
        RecvClientPartialMainAddCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckPartialMainAdd;
          client->Send(ackMsg);
        }
        break;
      case ThreshMsgTypes::SendDecryptPartialLeadAdd:

        std::cout << "[" << client->GetID() << "]: SendDecryptPartialLeadAdd\n";
        // receive ciphertext
        // store it in the ClientA's data structure.
        RecvClientPartialLeadAddCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckPartialLeadAdd;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendDecryptPartialMainMult:

        std::cout << "[" << client->GetID()
                  << "]: SendDecryptPartialMainMult\n";
        // receive ciphertext
        // store it in the ClientB's data structure.
        RecvClientPartialMainMultCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckPartialMainMult;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendDecryptPartialLeadMult:

        std::cout << "[" << client->GetID()
                  << "]: SendDecryptPartialLeadMult\n";
        // receive ciphertext
        // store it in the ClientA's data structure.
        RecvClientPartialLeadMultCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckPartialLeadMult;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendDecryptPartialMainSum:

        std::cout << "[" << client->GetID() << "]: SendDecryptPartialMainSum\n";
        // receive ciphertext
        // store it in the ClientB's data structure.
        RecvClientPartialMainSumCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckPartialMainSum;
          client->Send(ackMsg);
        }
        break;

      case ThreshMsgTypes::SendDecryptPartialLeadSum:

        std::cout << "[" << client->GetID() << "]: SendDecryptPartialLeadSum\n";
        // receive ciphertext
        // store it in the ClientA's data structure.
        RecvClientPartialLeadSumCT(client, msg);
        {
          // send acknowledgement
          olc::net::message<ThreshMsgTypes> ackMsg;
          ackMsg.header.id = ThreshMsgTypes::AckPartialLeadSum;
          client->Send(ackMsg);
        }
        break;

	case ThreshMsgTypes::DisconnectClient:

	  std::cout << "[" << client->GetID() << "]: DisconnectClient\n";
	  decrementNumClients();
	  exitIfNoClients();
	  break;
	  
      default:
        std::cout << "[" << client->GetID() << "]: unprocessed message\n";
    }
  }

  void InitializeCC(void) {
    PROFILELOG("[SERVER] Initializing");
    TimeVar t;  // time benchmarking variables
    PROFILELOG("[SERVER] Generating crypto context");
    TIC(t);

	usint init_size = 4;
	usint batchSize = 16;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(init_size-1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);

	m_serverCC = GenCryptoContext(parameters);
    // enable features that you wish to use
    m_serverCC->Enable(PKE);
    m_serverCC->Enable(KEYSWITCH);
    m_serverCC->Enable(LEVELEDSHE);
    m_serverCC->Enable(ADVANCEDSHE);
    m_serverCC->Enable(MULTIPARTY);

    PROFILELOG("[SERVER]: elapsed time " << TOC_MS(t) << "msec.");
  }

  void SendClientCC(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending cryptocontext to [" << client->GetID() << "]:");
    Serial::Serialize(m_serverCC, os, SerType::BINARY);

    olc::net::message<ThreshMsgTypes> msg;
    msg.header.id = ThreshMsgTypes::SendCC;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd1PubKey(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!A_Rnd1PubKeyRecd) {
      std::cout << "[SERVER] sending NackRnd1PubKey to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd1PubKey;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 1 Public Key to [" << client->GetID()
                                                      << "]:");
    Serial::Serialize(A_Rnd1PublicKey, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd1PubKey;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd1evalMultKey(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;

    if (!A_evalMultKeyRecd) {
      std::cout << "[SERVER] sending NackRnd1evalMultKey to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd1evalMultKey;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 1 EvalMultKey to [" << client->GetID()
                                                       << "]:");
    Serial::Serialize(A_evalMultKey, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd1evalMultKey;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd1evalSumKeys(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;

    if (!A_evalSumKeys) {
      std::cout << "[SERVER] sending NackRnd1evalSumKeys to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd1evalSumKeys;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 1 EvalSumKeys to [" << client->GetID()
                                                       << "]:");
    Serial::Serialize(A_evalSumKeys, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd1evalSumKeys;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd2PubKey(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!B_Rnd2PublicKeyRecd) {
      std::cout << "[SERVER] sending NackRnd2SharedKey to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd2SharedKey;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 2 Public Key to [" << client->GetID()
                                                      << "]:");
    Serial::Serialize(B_Rnd2PublicKey, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd2SharedKey;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd2evalMultKeyAB(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!B_evalMultKeyABRecd) {
      std::cout << "[SERVER] sending NackRnd2EvalMultAB to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd2EvalMultAB;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 2 EvalMultKeyAB to [" << client->GetID()
                                                         << "]:");
    Serial::Serialize(B_evalMultKeyAB, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd2EvalMultAB;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd2evalMultKeyBAB(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!B_evalMultKeyBABRecd) {
      std::cout << "[SERVER] sending NackRnd2EvalMultBAB to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd2EvalMultBAB;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 2 EvalMultKeyBAB to [" << client->GetID()
                                                          << "]:");
    Serial::Serialize(B_evalMultKeyBAB, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd2EvalMultBAB;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd2evalSumKeysJoin(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!B_evalSumKeysJoin) {
      std::cout << "[SERVER] sending NackRnd2EvalSumKeysJoin to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd2EvalSumKeysJoin;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 2 EvalSumKeysJoin to [" << client->GetID()
                                                           << "]:");
    Serial::Serialize(B_evalSumKeysJoin, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd2EvalSumKeysJoin;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientRnd3evalMultFinal(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!A_evalMultFinalRecd) {
      std::cout << "[SERVER] sending NackRnd3evalMultFinal to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackRnd3evalMultFinal;
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending Round 3 evalMultFinal to [" << client->GetID()
                                                         << "]:");
    Serial::Serialize(A_evalMultFinal, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendRnd3EvalMultFinal;
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void SendClientCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client, int num) {
    std::string s;
    std::ostringstream os(s);
    olc::net::message<ThreshMsgTypes> msg;
    if (!B_CTreceived[num]) {
      if (num == 0) {
        std::cout << "[SERVER] sending NackCT1 to [" << client->GetID()
                  << "]:\n";
        msg.header.id = ThreshMsgTypes::NackCT1;
      } else if (num == 1) {
        std::cout << "[SERVER] sending NackCT2 to [" << client->GetID()
                  << "]:\n";
        msg.header.id = ThreshMsgTypes::NackCT2;
      } else if (num == 2) {
        std::cout << "[SERVER] sending NackCT3 to [" << client->GetID()
                  << "]:\n";
        msg.header.id = ThreshMsgTypes::NackCT3;
      }
      client->Send(msg);
      return;
    }

    OPENFHE_DEBUG("[SERVER]: sending CT" << num << " to [" << client->GetID() << "]:");
    Serial::Serialize(B_CipherTexts[num], os, SerType::BINARY);

    if (num == 0) {
      msg.header.id = ThreshMsgTypes::SendCT1;
    } else if (num == 1) {
      msg.header.id = ThreshMsgTypes::SendCT2;
    } else if (num == 2) {
      msg.header.id = ThreshMsgTypes::SendCT3;
    }
    msg << os.str();  // push the string onto the message.

    client->Send(msg);
  }

  void RecvClientAPublicKey(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the public key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Rnd1 public key of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(A_Rnd1PublicKey, is, SerType::BINARY);
    A_Rnd1PubKeyRecd = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientAevalMultKey(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the evalmult key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Rnd1 evalmultkey of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(A_evalMultKey, is, SerType::BINARY);
    A_evalMultKeyRecd = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientAevalSumKeys(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the evalsumkeys from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Rnd1 evalsumkeys of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(A_evalSumKeys, is, SerType::BINARY);
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientBPublicKey(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the public key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Round 2 public key of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(B_Rnd2PublicKey, is, SerType::BINARY);
    B_Rnd2PublicKeyRecd = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientBevalMultKeyAB(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the evalMultAB key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Round 2 evalMultKeyAB key of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(B_evalMultKeyAB, is, SerType::BINARY);
    B_evalMultKeyABRecd = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientBevalMultKeyBAB(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the evalMultBAB key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Round 2 evalMultKeyBAB of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(B_evalMultKeyBAB, is, SerType::BINARY);
    B_evalMultKeyBABRecd = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientBevalSumKeysJoin(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the evalsumkeysjoin from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Round 2 evalSumKeysJoin of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(B_evalSumKeysJoin, is, SerType::BINARY);
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientAevalMultFinal(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the evalMultFinal key from this client,
    // and store it in the data structure
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());

    OPENFHE_DEBUG("[SERVER] read Round 3 evalMultFinal of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");
    Serial::Deserialize(A_evalMultFinal, is, SerType::BINARY);
    A_evalMultFinalRecd = true;
    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
  }

  void RecvClientCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the CT from this client,
    // and store it in the data structure with this client as key
    // note a more complex server could store the key in a
    // data structure indexed by the client->GetID()
    unsigned int msgSize(msg.body.size());
    CT ct;
    OPENFHE_DEBUG("[SERVER] read CT of " << msgSize << " bytes");
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());

    // make an istringstream from the message
    std::istringstream is(std::string(msg.body.begin(), msg.body.end()));
    OPENFHE_DEBUG("SERVER istringstream.str.size(): " << is.str().size());

    // NOTE Deserialize needs a basic_istream<char>
    OPENFHE_DEBUG("[SERVER] Deserialize");

    Serial::Deserialize(ct, is, SerType::BINARY);

    B_CipherTexts.push_back(ct);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    B_CTreceived.push_back(true);
  }

  CT EvaluateAddCiphertext(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    CT ciphertextAdd12;
    CT ciphertextAdd123;
    olc::net::message<ThreshMsgTypes> msg;
    if (!B_CTreceived[0]) {
      std::cout << "[SERVER] sending NackCT1 to [" << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackCT1;
      client->Send(msg);
      return ciphertextAdd123;
    } else if (!B_CTreceived[1]) {
      std::cout << "[SERVER] sending NackCT2 to [" << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackCT2;
      client->Send(msg);
      return ciphertextAdd123;

    } else if (!B_CTreceived[2]) {
      std::cout << "[SERVER] sending NackCT3 to [" << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackCT3;
      client->Send(msg);
      return ciphertextAdd123;
    }
    ciphertextAdd12 = m_serverCC->EvalAdd(B_CipherTexts[0], B_CipherTexts[1]);
    ciphertextAdd123 = m_serverCC->EvalAdd(ciphertextAdd12, B_CipherTexts[2]);

    EvalAddCTDone = true;
    // auto ciphertextEvalSum = cc->EvalSum(ciphertext3, batchSize);
    return ciphertextAdd123;
  }

  CT EvaluateMultCiphertext(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    m_serverCC->InsertEvalMultKey({ThreshServer::A_evalMultFinal});

    auto ciphertextMultTemp =
        m_serverCC->EvalMult(B_CipherTexts[0], B_CipherTexts[2]);
    auto ciphertextMult = m_serverCC->ModReduce(ciphertextMultTemp);

    EvalMultCTDone = true;
    // auto ciphertextEvalSum = cc->EvalSum(ciphertext3, batchSize);
    return ciphertextMult;
  }

  void SendClientAddCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the PrivateKey does not yet exist, send a Nack

    EvalAddCT = EvaluateAddCiphertext(client);
    if (!EvalAddCTDone) {
      std::cout << "[SERVER] sending NackAddCT to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackAddCT;
      client->Send(msg);
      return;
    }
    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending eval add CT to [" << client->GetID() << "]:");
    Serial::Serialize(EvalAddCT, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendAddCT;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void SendClientMultCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the PrivateKey does not yet exist, send a Nack
    EvalMultCT = EvaluateMultCiphertext(client);
    if (!EvalMultCTDone) {
      std::cout << "[SERVER] sending NackMultCT to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackMultCT;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending eval mult CT to [" << client->GetID() << "]:");
    Serial::Serialize(EvalMultCT, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendMultCT;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  CT EvaluateSumCiphertext(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    m_serverCC->InsertEvalSumKey(B_evalSumKeysJoin);

    // compute ciphertextSum[0] = ciphertext3[0]+...+ciphertext[batchsize-1]
    // compute ciphertextSum[1] = ciphertext3[1]+...+ciphertext3[batchsize] and
    // so on.
    auto ciphertextEvalSum = m_serverCC->EvalSum(B_CipherTexts[2], batchSize);

    EvalSumCTDone = true;
    return ciphertextEvalSum;
  }

  void SendClientSumCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the PrivateKey does not yet exist, send a Nack
    EvalSumCT = EvaluateSumCiphertext(client);
    if (!EvalSumCTDone) {
      std::cout << "[SERVER] sending NackSumCT to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackSumCT;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending eval sum CT to [" << client->GetID() << "]:");
    Serial::Serialize(EvalSumCT, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendSumCT;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }
  void SendClientDecryptMainMult(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the partial decrypt does not yet exist, send a Nack
    if (!Partial_MainMultRecd) {
      std::cout << "[SERVER] sending NackPartialMainMult to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackPartialMainMult;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending partial decrypt main mult to [" << client->GetID()
                                                             << "]:");
    Serial::Serialize(Partial_MainMult, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendDecryptMainMult;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void SendClientDecryptLeadMult(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the partial decrypt does not yet exist, send a Nack
    if (!Partial_LeadMultRecd) {
      std::cout << "[SERVER] sending NackPartialLeadMult to ["
                << client->GetID() << "]:\n";
      msg.header.id = ThreshMsgTypes::NackPartialLeadMult;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending partial decrypt lead mult to [" << client->GetID()
                                                             << "]:");
    Serial::Serialize(Partial_LeadMult, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendDecryptLeadMult;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void SendClientDecryptMainAdd(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the partial decrypt does not yet exist, send a Nack
    if (!Partial_MainAddRecd) {
      std::cout << "[SERVER] sending NackPartialMainAdd to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackPartialMainAdd;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending partial decrypt main add to [" << client->GetID()
                                                            << "]:");
    Serial::Serialize(Partial_MainAdd, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendDecryptMainAdd;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void SendClientDecryptLeadAdd(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the partial decrypt does not yet exist, send a Nack
    if (!Partial_LeadAddRecd) {
      std::cout << "[SERVER] sending NackPartialLeadAdd to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackPartialLeadAdd;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending partial decrypt lead add to [" << client->GetID()
                                                            << "]:");
    Serial::Serialize(Partial_LeadAdd, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendDecryptLeadAdd;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void SendClientDecryptMainSum(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the partial decrypt does not yet exist, send a Nack
    if (!Partial_MainSumRecd) {
      std::cout << "[SERVER] sending NackPartialMainSum to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackPartialMainSum;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending partial decrypt main sum to [" << client->GetID()
                                                            << "]:");
    Serial::Serialize(Partial_MainSum, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendDecryptMainSum;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void SendClientDecryptLeadSum(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client) {
    olc::net::message<ThreshMsgTypes> msg;
    // if the partial decrypt does not yet exist, send a Nack
    if (!Partial_LeadSumRecd) {
      std::cout << "[SERVER] sending NackPartialLeadSum to [" << client->GetID()
                << "]:\n";
      msg.header.id = ThreshMsgTypes::NackPartialLeadSum;
      client->Send(msg);
      return;
    }

    std::string s;
    std::ostringstream os(s);
    OPENFHE_DEBUG("[SERVER]: sending partial decrypt lead sum to [" << client->GetID()
                                                            << "]:");
    Serial::Serialize(Partial_LeadSum, os, SerType::BINARY);

    msg.header.id = ThreshMsgTypes::SendDecryptLeadSum;
    msg << os.str();  // push the string onto the message.
    OPENFHE_DEBUG("[SERVER]: msg.size() " << msg.size());
    OPENFHE_DEBUG("[SERVER]: msg.body.size() " << msg.body.size());
    client->Send(msg);
  }

  void RecvClientPartialMainAddCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the partially decrypted CT from this client,
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

    Serial::Deserialize(Partial_MainAdd, is, SerType::BINARY);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    Partial_MainAddRecd = true;
  }

  void RecvClientPartialMainMultCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the partially decrypted CT from this client,
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

    Serial::Deserialize(Partial_MainMult, is, SerType::BINARY);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    Partial_MainMultRecd = true;
  }

  void RecvClientPartialMainSumCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the partially decrypted CT from this client,
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

    Serial::Deserialize(Partial_MainSum, is, SerType::BINARY);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    Partial_MainSumRecd = true;
  }

  void RecvClientPartialLeadAddCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the partially decrypted CT from this client,
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

    Serial::Deserialize(Partial_LeadAdd, is, SerType::BINARY);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    Partial_LeadAddRecd = true;
  }

  void RecvClientPartialLeadMultCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the partially decrypted CT from this client,
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

    Serial::Deserialize(Partial_LeadMult, is, SerType::BINARY);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    Partial_LeadMultRecd = true;
  }

  void RecvClientPartialLeadSumCT(
      std::shared_ptr<olc::net::connection<ThreshMsgTypes>> client,
      olc::net::message<ThreshMsgTypes>& msg) {
    // receive the partially decrypted CT from this client,
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

    Serial::Deserialize(Partial_LeadSum, is, SerType::BINARY);

    OPENFHE_DEBUG("[SERVER] Done");
    assert(is.good());
    Partial_LeadSumRecd = true;
  }

  void incrementNumClients(void){
	numClient++;
    std::cout << "[Server] Incrementing # clients, now "<< numClient << "\n";
  }

  void decrementNumClients(void){
	numClient--;
    std::cout << "[Server] Decrementing # clients, now "<< numClient << "\n";
  }
  void exitIfNoClients(void){
	if (!numClient) {
	  std::cout << "[Server] Shutting down\n";
	  exit(EXIT_SUCCESS);
	}
  }

private:
  // Server state
  CC m_serverCC;
  usint numClient = 0; //keeps track of # clients, and when it goes back to zero, exits
  
  usint batchSize = 16;  // batch size for vector sum computation

  // a full up server would have lists of all the clients,
  // and their approved connections,
  // but we will only keep track of one pair in this example

  // public keys of Clients Alice and Bob
  PubKey A_Rnd1PublicKey, B_Rnd2PublicKey;

  // evaluation keys for multiplication in rounds1,2,3 from Alice and Bob and
  // flags for marking received
  EvKey A_evalMultKey, B_evalMultKeyAB, B_evalMultKeyBAB, A_evalMultFinal;
  bool A_Rnd1PubKeyRecd, A_evalMultKeyRecd, B_Rnd2PublicKeyRecd,
      B_evalMultKeyABRecd, B_evalMultKeyBABRecd, A_evalMultFinalRecd;

  // evaluation keys for vector sum
  std::shared_ptr<std::map<usint, EvKey>> A_evalSumKeys, B_evalSumKeysJoin;

  // ciphertexts from Bob and flags for receiving the ciphertexts
  std::vector<CT> B_CipherTexts;
  std::vector<bool> B_CTreceived;

  // evaluation ciphertexts if the server does the computation
  CT EvalAddCT, EvalMultCT, EvalSumCT;

  CT Partial_LeadAdd, Partial_MainAdd, Partial_LeadMult, Partial_MainMult,
      Partial_LeadSum, Partial_MainSum;
  bool EvalAddCTDone = false, EvalMultCTDone = false, EvalSumCTDone = false;
  bool Partial_LeadAddRecd = false, Partial_MainAddRecd = false,
       Partial_LeadMultRecd = false, Partial_MainMultRecd = false;
  bool Partial_LeadSumRecd = false, Partial_MainSumRecd = false;
};

#endif  // THRESH_SERVER_H
