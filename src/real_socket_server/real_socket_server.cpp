// @file real-socket-server - code to simulate a server to show an example of encrypted
// server-client processing relationships via sockets.
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

// @copyright Copyright (c) 2020, 2022 Duality Technologies Inc.
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

#include "utils_socket.h"
#include "openfhe.h"

using namespace lbcrypto;


/**
 * Mocks a server which supports some basic operations
 */
class Server {
 public:
  /**
   * Instantiation of our "Server"
   * @param multDepth - integer describing the multiplicative depth for our CKKS
   * scheme
   * @param scaleFactorBits - scaleFactor
   * @param batchSize - size of the batch
   */
  Server(int multDepth, int scaleFactorBits, int batchSize);
  /**
   * sendCCAndKeys send the CryptoContext and keys to client via socket s
   */
  void sendCCAndKeys(tcp::socket &s);

  /**
   * generateAndSendData - read from some internal location, encrypt then send it off
   * for some client to process
   *    - in this case we write the data directly to socket s
   */
  void generateAndSendData(tcp::socket &s);

  /**
   * receiveAndVerifyData - receive data from client and
   * verify it. 
   *
   */
  void receiveAndVerifyData(tcp::socket &s);

 private:
  /**
   * readData - reads data from a local source (in reality just generate it) 
   * @return complex matrix of values of interest
   */
  complexMatrix readData(void);

  /**
   * packAndEncrypt - pack messages (into plaintexts) and encrypt them (into
   * ciphertexts)
   * @param matrixOfData - matrix of raw data, unpacked data. Likely directly
   * from a data lake
   * @return - a vector of ciphertexts (which are themselves like vectors)
   */
  ciphertextMatrix packAndEncrypt(const complexMatrix &matrixOfData);

  /**
   * actually writeData contained in matrix to socket s
   * @param s socket 
   * @param matrix
   */
  void writeData(tcp::socket &s, const ciphertextMatrix &matrix);

  KPair m_kp; //contains secret and public key!
  CC m_cc;
  int m_vectorSize = 0;
};

/////////////////////////////////////////////////////////////////
// Public Interface
/////////////////////////////////////////////////////////////////

Server::Server(int multDepth, int scaleModSize, int batchSize) {

   CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
	
  m_cc = GenCryptoContext(parameters);

  m_cc->Enable(PKE);
  m_cc->Enable(KEYSWITCH);
  m_cc->Enable(LEVELEDSHE);

  m_kp = m_cc->KeyGen();
  m_cc->EvalMultKeyGen(m_kp.secretKey);
  m_cc->EvalAtIndexKeyGen(m_kp.secretKey, {1, 2, -1, -2});

}

/**
 * generateAndSendData - process a request from a client and "send"
 * data over by writing to a location
 *
 */
void Server::generateAndSendData(tcp::socket &s) {
  auto rawData = readData();
  auto ciphertexts = packAndEncrypt(rawData);
  writeData(s, ciphertexts);
}

/**
 * receiveAndVerifyData - "receive" a payload from the client and verify the results
 */
void Server::receiveAndVerifyData(tcp::socket &s) {
  /////////////////////////////////////////////////////////////////
  // Receive the data and decrpyt all of it
  /////////////////////////////////////////////////////////////////
  if (m_vectorSize == 0) {
    std::cerr << "SERVER: Must have sent data to client first ";
    std::cerr
        << "which initiates a vector size tracker (dimensionality of data)";
    std::cerr << "for use in decryption."
              << "\n";
    exit(EXIT_FAILURE);
  }
  CT serverCiphertextFromClient_Mult;
  CT serverCiphertextFromClient_Add;
  CT serverCiphertextFromClient_Rot;
  CT serverCiphertextFromClient_RogNeg;
  CT serverCiphertextFromClient_Vec;

  serverCiphertextFromClient_Mult = recvCT(s);
  serverCiphertextFromClient_Add = recvCT(s);
  serverCiphertextFromClient_Rot = recvCT(s);
  serverCiphertextFromClient_RogNeg = recvCT(s);
  serverCiphertextFromClient_Vec = recvCT(s);
  
  std::cout << "SERVER: Deserialized all processed encrypted data from client" << std::endl;

  Plaintext serverPlaintextFromClient_Mult;
  Plaintext serverPlaintextFromClient_Add;
  Plaintext serverPlaintextFromClient_Rot;
  Plaintext serverPlaintextFromClient_RotNeg;
  Plaintext serverPlaintextFromClient_Vec;

  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Mult,
                &serverPlaintextFromClient_Mult);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Add,
                &serverPlaintextFromClient_Add);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Rot,
                &serverPlaintextFromClient_Rot);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_RogNeg,
                &serverPlaintextFromClient_RotNeg);
  m_cc->Decrypt(m_kp.secretKey, serverCiphertextFromClient_Vec,
                &serverPlaintextFromClient_Vec);

  /////////////////////////////////////////////////////////////////
  // Retrive the values from the CKKS packed Values
  /////////////////////////////////////////////////////////////////

  serverPlaintextFromClient_Mult->SetLength(m_vectorSize);
  serverPlaintextFromClient_Add->SetLength(m_vectorSize);
  serverPlaintextFromClient_Vec->SetLength(m_vectorSize);
  serverPlaintextFromClient_Rot->SetLength(m_vectorSize + 1);
  serverPlaintextFromClient_RotNeg->SetLength(m_vectorSize + 1);

  complexVector multExpected = {12.5, 27, 43.5, 62};
  complexVector addExpected = {13.5, 15.5, 17.5, 19.5};
  complexVector vecExpected = {1, 2, 3, 4};
  complexVector rotExpected = {2, 3, 4, 0.0000, 0.00000};
  complexVector negRotExpected = {0.00000, 1, 2, 3, 4};

  auto multFlag = validateData(
      serverPlaintextFromClient_Mult->GetCKKSPackedValue(), multExpected);
  std::cout << "Mult correct: " << (multFlag ? "Yes" : "No ") << "\n";
  auto addFlag = validateData(
      serverPlaintextFromClient_Add->GetCKKSPackedValue(), addExpected);
  std::cout << "Add correct: " << (addFlag ? "Yes" : "No ") << "\n";
  auto vecFlag = validateData(
      serverPlaintextFromClient_Vec->GetCKKSPackedValue(), vecExpected);
  std::cout << "Vec encryption correct: " << (vecFlag ? "Yes" : "No ") << "\n";
  auto rotFlag = validateData(
      serverPlaintextFromClient_Rot->GetCKKSPackedValue(), rotExpected);
  std::cout << "Rotation correct: " << (rotFlag ? "Yes" : "No ") << "\n";
  auto negRotFlag = validateData(
      serverPlaintextFromClient_RotNeg->GetCKKSPackedValue(), negRotExpected);
  std::cout << "Negative rotation correct: " << (negRotFlag ? "Yes" : "No ")
            << "\n";
}

/////////////////////////////////////////////////////////////////
// Private Interface
/////////////////////////////////////////////////////////////////

/**
 * readData - mock reading data from a data base on the server. We
 * just use hardcoded vectors
 * @return
 *  vector of hard-coded vectors (basically a matrix)
 */
std::vector<std::vector<std::complex<double>>> Server::readData(void) {

  complexVector vec1 = {1.0, 2.0, 3.0, 4.0};
  complexVector vec2 = {12.5, 13.5, 14.5, 15.5};

  m_vectorSize = vec1.size();

  return {
      vec1,
      vec2,
  };
}

/**
 * packAndEncrypt - pack the data into a vector and then encrypt it
 * @param matrixOfData
 * @return
 */
ciphertextMatrix Server::packAndEncrypt(const complexMatrix &matrixOfData) {
  auto container =
      ciphertextMatrix(matrixOfData.size(), CT());

  unsigned int ind = 0;
  for (auto &v : matrixOfData) {
    container[ind] =
        m_cc->Encrypt(m_kp.publicKey, m_cc->MakeCKKSPackedPlaintext(v));
    ind += 1;
  }
  return container;
}

/**
 * sendCCAndKeys - send the cc and keys specified locations.
 * @param conf
 */
void Server::sendCCAndKeys(tcp::socket &s) {

  sendCC(s, m_cc);
  sendPublicKey(s, m_kp.publicKey);
  sendEvalMultKey(s, m_cc);
  sendEvalAutomorphismKey(s, m_cc);
}
/**
 * writeData - write a matrix of data to the specified locations.
 * @param s socket
 * @Param matrix of data
 */
void Server::writeData(tcp::socket &s, const ciphertextMatrix &matrix) {

  std::cout << "SERVER: sending encrypted data" << std::endl;
  for (size_t i = 0; i < matrix.size(); i++){
	sendCT(s, matrix[i]);
	std::cout << "SERVER: ciphertext " << i << " serialized" << std::endl;
  }
}


/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[]) {
  TimeVar t;
  
  try {
	if (argc != 2) {
	  std::cerr << "Usage: real-socket-server <port>\n";
	  return 1;
	}
	const int multDepth = 5;
	const int scaleFactorBits = 40;
	const usint batchSize = 32;
	Server server = Server(multDepth, scaleFactorBits, batchSize);
	TIC(t);

	boost::asio::io_service io_service;

	std::cout << "SERVER: creating acceptor for " << argv[1] << std::endl;
	tcp::acceptor a(io_service, tcp::endpoint(tcp::v4(), atoi( argv[1])));
	std::cout << "SERVER: accepting socket" << std::endl;

	tcp::socket s(io_service);
	a.accept(s);

	std::cout << "SERVER: sending CC and Keys" << std::endl;
	server.sendCCAndKeys(s);

	std::cout << "SERVER: Generate and Send data" << std::endl;  
	server.generateAndSendData(s);

	std::cout << "SERVER: Receive and Verify data" << std::endl;
	server.receiveAndVerifyData(s);

  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  double totalTimeMSec = TOC_MS(t);
  std::cout << "SERVER: Total time: " << totalTimeMSec << " mSec" << std::endl;  
  return EXIT_SUCCESS;
}
