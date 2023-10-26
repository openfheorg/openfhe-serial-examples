// @file real-client - code to simulate a client to show an example of encrypted
// server-client processing relationships.
//
//The server serializes contexts, public key and processing keys for
// the client to then load. It then generates and encrypts some data
// to send to the client. The client loads the crypto context and
// keys, then operates on the encrypted data, encrypts additional
// data, and sends the results back to the server.  Finally, the
// server decrypts the result and in this demo verifies that results
// are correct.
// 
// @author: Ian Quah, Dave Cousins
// TPOC: contact@openfhe-crypto.org

// @copyright Copyright (c) 2020, 2023 Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "utils.h"
#include "openfhe.h"

using namespace lbcrypto;
using CT = Ciphertext<DCRTPoly>;

std::tuple<CryptoContext<DCRTPoly>, PublicKey<DCRTPoly>>
receiveCCAndKeys(void) {
  /////////////////////////////////////////////////////////////////
  // NOTE: ReleaseAllContexts is imperative; it ensures that the environment
  // is cleared before loading anything. The function call ensures we are not
  // keeping any contexts in the process. Use it before creating a new CC
  /////////////////////////////////////////////////////////////////
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContext<DCRTPoly> clientCC;
  if (!Serial::DeserializeFromFile(GConf.ccLocation,
				   clientCC,
				   SerType::BINARY)) {
    std::cerr << "CLIENT: cannot read serialized data from: "
              << GConf.DATAFOLDER << "/cryptocontext.txt" << std::endl;
    std::exit(1);
  }
  fRemove(GConf.ccLocation);
  
  /////////////////////////////////////////////////////////////////
  // NOTE: the following 2 lines are essential
  // It is possible that the keys are carried over in the cryptocontext
  // serialization so clearing the keys is important
  /////////////////////////////////////////////////////////////////

  clientCC->ClearEvalMultKeys();
  clientCC->ClearEvalAutomorphismKeys();

  PublicKey<DCRTPoly> clientPublicKey;
  if (!Serial::DeserializeFromFile(GConf.pubKeyLocation,
				   clientPublicKey,
				   SerType::BINARY)) {
    std::cerr << "CLIENT: cannot read serialized data from: "
              << GConf.DATAFOLDER << "/cryptocontext.txt" << std::endl;
    std::exit(1);
  }
  fRemove(GConf.pubKeyLocation);
  std::cout << "CLIENT: public key deserialized" << std::endl;

  std::ifstream multKeyIStream(GConf.multKeyLocation,
			       std::ios::in | std::ios::binary);
  if (!multKeyIStream.is_open()) {
    std::cerr << "CLIENT: cannot read serialization from "
              << GConf.multKeyLocation
              << std::endl;
    std::exit(1);
  }
  if (!clientCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
    std::cerr << "CLIENT: Could not deserialize eval mult key file"
              << std::endl;
    std::exit(1);
  }
  multKeyIStream.close();
  fRemove(GConf.multKeyLocation);
  std::cout << "CLIENT: Relinearization keys from server deserialized." << std::endl;

  std::ifstream rotKeyIStream(GConf.rotKeyLocation,
			      std::ios::in | std::ios::binary);
  if (!rotKeyIStream.is_open()) {
    std::cerr << "CLIENT: Cannot read serialization from "
              << GConf.multKeyLocation
              << std::endl;
    std::exit(1);
  }

  if (!clientCC->DeserializeEvalAutomorphismKey(rotKeyIStream,
                                                SerType::BINARY)) {
    std::cerr << "CLIENT: Could not deserialize eval rot key file" << std::endl;
    std::exit(1);
  }
  rotKeyIStream.close();
  fRemove(GConf.rotKeyLocation);

  return std::make_tuple(clientCC, clientPublicKey);
}

CT receiveCT(const std::string location){
  CT c1;
  if (!Serial::DeserializeFromFile(location, c1,
				   SerType::BINARY)) {
    std::cerr << "CLIENT: Cannot read serialization from " << location << std::endl;
    removeLock(GConf.clientLock, GConf.CLIENT_LOCK);
    std::exit(EXIT_FAILURE);
  }
  fRemove(location);
  return c1;
}

void computeAndSendData(CryptoContext<DCRTPoly> &clientCC,
			CT &clientC1,
			CT &clientC2,
			PublicKey<DCRTPoly> &clientPublicKey) {

  std::cout << "CLIENT: Applying operations on data" << std::endl;
  auto clientCiphertextMult = clientCC->EvalMult(clientC1, clientC2);
  auto clientCiphertextAdd = clientCC->EvalAdd(clientC1, clientC2);
  auto clientCiphertextRot = clientCC->EvalAtIndex(clientC1, 1);
  auto clientCiphertextRotNeg = clientCC->EvalAtIndex(clientC1, -1);

  // Now, we want to simulate a client who is encrypting data for the server to
  // decrypt. E.g weights of a machine learning algorithm

  std::cout << "CLIENT: encrypting a vector" << std::endl;
  complexVector clientVector1 = {1.0, 2.0, 3.0, 4.0};
  if (clientVector1.size() != VECTORSIZE) {
    std::cerr << "clientVector1 size was modified. Must be of length 4"
	      << std::endl;
    exit(1);
  }
  auto clientPlaintext1 = clientCC->MakeCKKSPackedPlaintext(clientVector1);
  auto clientInitiatedEncryption =
    clientCC->Encrypt(clientPublicKey, clientPlaintext1);
  Serial::SerializeToFile(GConf.cipherMultLocation,
			  clientCiphertextMult, SerType::BINARY);
  Serial::SerializeToFile(GConf.cipherAddLocation,
			  clientCiphertextAdd, SerType::BINARY);
  Serial::SerializeToFile(GConf.cipherRotLocation,
			  clientCiphertextRot, SerType::BINARY);
  Serial::SerializeToFile(GConf.cipherRotNegLocation,
			  clientCiphertextRotNeg, SerType::BINARY);
  Serial::SerializeToFile(GConf.clientVectorLocation,
			  clientInitiatedEncryption, SerType::BINARY);
}
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

int main() {

  // note GConf is a global structure defined in utils.h
  
  std::cout << "This program requires the subdirectory "
            << GConf.DATAFOLDER << "' to exist, otherwise you will get "
            << "an error writing serializations." << std::endl;
  /////////////////////////////////////////////////////////////////
  // Actual client work
  /////////////////////////////////////////////////////////////////


  // basically we need the server to be up and running first to write out all
  // the serializations
  std::cout << "CLIENT: Open server lock" << std::endl;
  GConf.serverLock = openLock(GConf.SERVER_LOCK);
  
  std::cout << "CLIENT: create and acquire client lock" << std::endl;
  GConf.clientLock = createAndAcquireLock(GConf.CLIENT_LOCK);
  releaseLock(GConf.clientLock,GConf.CLIENT_LOCK);

  std::cout << "CLIENT: acquire server lock" << std::endl;

  // the client will sleep until the server is done with the lock
  acquireLock(GConf.serverLock,GConf.SERVER_LOCK);
  std::cout << "CLIENT: Acquired server lock. Getting serialized CryptoContext and keys" << std::endl;


  auto ccAndPubKeyAsTuple = receiveCCAndKeys();
  auto clientCC = std::get<CRYPTOCONTEXT_INDEX>(ccAndPubKeyAsTuple);
  auto clientPublicKey = std::get<PUBLICKEY_INDEX>(ccAndPubKeyAsTuple);
  
  std::cout << "CLIENT: Getting ciphertexts" << std::endl;
  CT clientC1 = receiveCT(GConf.cipherOneLocation);
  CT clientC2 = receiveCT(GConf.cipherTwoLocation);

  std::cout << "CLIENT: Computing and Serializing results" << std::endl;
  computeAndSendData(clientCC, clientC1, clientC2, clientPublicKey);

  std::cout << "CLIENT: Releasing Server lock" << std::endl;
  releaseLock(GConf.serverLock,GConf.SERVER_LOCK);
  std::cout << "CLIENT: Releasing Client lock" << std::endl;
  releaseLock(GConf.clientLock, GConf.CLIENT_LOCK);
  // the server will clean up all locks and files. 
  std::cout << "CLIENT: Exiting" << std::endl;

}
