#define _WIN32_WINNT 0x501
#include <ws2tcpip.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#define USE_IPV6 false                                                              // Sets whether to use IPv6 (true) or IPv4 (false).
#define DEFAULT_PORT "1234"                                                         // The port number used for TCP connection.
#define BUFFER_SIZE 800                                                             // Size of buffer to receive and send messages with.
#define WSVERS MAKEWORD(2,2)

using namespace std;


/**
 *  Function declarations.
 */
int  tcpConnect(SOCKET &s, int argc, char *argv[]);                                 // Sets up listening socket for TCP connection with client.
int  startWSA();                                                                    // Start WSA.
int  getServerAddressInfo(struct addrinfo *&result, int argc, char *argv[], char *portNum); // Gets this server's address info.
int  createSocket(SOCKET &s, struct addrinfo *result);                              // Creates the socket.
int  bindSocket(SOCKET &s, struct addrinfo *result);                                // Binds the socket.
int  startListening(SOCKET s, char *portNum);                                       // Starts listening for client connections on socket.
int  communicateWithNewClient(SOCKET s, long *encryptKeyCA, long *encryptKeyServer);// Connects with a new client and communicates over encrypted channel.
int  acceptNewClient(SOCKET s, SOCKET &ns, char *clientHost, char *clientService);  // Accepts a new client connection and allocates the socket ns for communication.
int  sendServerPublicKey(SOCKET s, long *encryptKeyCA, long *encryptKeyServer);     // Sends encrypted public key of server to client.
void encryptCA(char *sendBuffer, int &messageLength, int d, int n);                 // Encrypt method used to encrypt the certificate authority's message.
long repeatsquare(long x, long eORd, long n);                                       // Repeat Square method as found in Assignment guide.
void createStringToSend(char *sendBuffer, long *encryptedBuffer, int &messageLength);   // Creates a string of char representation of long values from the encrypted long buffer.
int  sendMessage(SOCKET s, char *sendBuffer, int strlen);                           // Sends buffer to client.
void displayCharBuffer(char *charBuffer, int messageLength);                        // Displays character buffer in human readable format to user.
int  receiveMessage(SOCKET s, char *receiveBuffer, int messageLength);              // Receives a message from the client and displays message.
void removeTerminatingCharacters(char *charBuffer, int &messageLength);             // Removes terminating characters "\r\n" from messages.
int  receiveACK(SOCKET s, char *expectedACK);                                       // Receives message from user and compares to expected ACK string.
int  simulateCASendingServerPublicKey(SOCKET s, long *encryptKeyCA, long *encryptKeyServer);    // Simulates the Certifcation Authority sending the server's public key to the client.
int  receiveNOnce(SOCKET s, long &nOnce);                                           // Receives the nOnce value from the client.
void receiveClientMessages(SOCKET s, long *encryptKeyServer, long nOnce, bool &clientConnected);    // Receives encrypted message from the client, decrypts them, and replies with the decrypted message.
int  receiveEncryptedMessage(SOCKET s, long *encryptedBuffer, int &messageLength, int &receivedMessageLength);  // Receives encrypted message and stores in encryptedBuffer.
void printBuffer(const char *header, char *buffer, int messageLength);              // Napoleon's print buffer method.
void decrypt(long *encryptedBuffer, char *receiveBuffer, int &messageLength, int d, int n, int nOnce);  // Decrypt method used to decrypt received encrypted messages.
long cbc(char charToEncrypt, long rand);                                            // Cypher Block Chain encryption.

