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
#define SEGMENT_SIZE 70                                                             // If fgets gets more than this number of bytes it segments the message.
#define WSVERS MAKEWORD(2,2)

using namespace std;


/**
 *  Function declarations.
 */
int  tcpConnect(SOCKET &s, int argc, char *argv[]);                                 // Setup TCP connection with server.
int  startWSA();                                                                    // Start WSA.
int  getServerAddressInfo(int argc, char *argv[], struct addrinfo *&result, char *portNum); // Gets the server's address info.
int  createSocket(SOCKET &s, struct addrinfo *result);                              // Creates the socket for connection to server.
int  getServerNameInfo(struct addrinfo *result, char *portNum);                     // Gets the name info of the server.
int  connectToServer(SOCKET &s, struct addrinfo *result, char *portNum);            // Connects socket to server.
int  receiveServerPublicKey(SOCKET &s, int caKeyE, int caKeyN, int &serverKeyE, int &serverKeyN);   // Receives and stores public key of server and sends ACK reply.
int  receiveKey(SOCKET s, int caKeyE, int caKeyN, int &serverKeyE, int &serverKeyN);    // Receives the message containing the server's public key information.
int  receiveEncryptedMessage(SOCKET s, long *encryptedBuffer, int &messageLength);  // Receives encrypted message and stores in encryptedBuffer.
void displayCharBuffer(char *charBuffer, int messageLength);                        // Displays character buffer in human readable format to user.
void decryptCA(long *encryptedBuffer, char *receiveBuffer, int &messageLength, int e, int n);   // Decrypt method used to decrypt received encrypted messages.
long repeatsquare(long x, long eORd, long n);                                       // Repeat Square method as found in Assignment guide.
int  sendMessage(SOCKET s, char *sendBuffer, int strlen);                           // Sends buffer to server.
int  receiveACK(SOCKET s, char *expectedACK);                                       // Receives message from user and compares to expected ACK string.
int  receiveMessage(SOCKET s, char *receiveBuffer, int messageLength);              // Receives a message from the server and displays message.
void removeTerminatingCharacters(char *charBuffer, int &messageLength);             // Removes terminating characters "\r\n" from messages.
int  sendNOnce(SOCKET s, long nOnce);                                               // Sends the nOnce to the server and waits for ACK.
int  sendUserMessages(SOCKET s, int serverKeyE, int serverKeyN, long nOnce);        // Gets input from user and sends as encrypted message to server.
int  getInput(char *inputBuffer, int &messageLength);                               // Gets input from user.
void encrypt(char *sendBuffer, int &messageLength, int e, int n, long nOnce);       // Encrypt method used to encrypt the message to be sent.
long cbc(char charToEncrypt, long rand);                                            // Cypher Block Chain encryption.
void createStringToSend(char *sendBuffer, long *encryptedBuffer, int &messageLength);   // Creates a string of char representation of long values from the encrypted long buffer.
void printBuffer(const char *header, char *buffer, int messageLength);              // Napoleon's print buffer method.

