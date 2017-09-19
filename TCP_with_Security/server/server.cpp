#include "server.h"

enum { KEY_E, KEY_D, KEY_N };                                                       // Used to access values in key arrays.


/**
 *  The main function, handles everything.
 */
int main(int argc, char *argv[]) {

    cout << "<<< TCP (CROSS-PLATFORM, IPv6-ready) SERVER, by Cai and Steve >>>" << endl;

    SOCKET s = INVALID_SOCKET;                                                      // The listening socket.

    int error = tcpConnect(s, argc, argv);                                          // Open the listening socket.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }

    long encryptKeyCA[3] = { 4297, 4633, 7171 };                                    // The key used to encrypt/decrypt Certification Authority messages: { e, d, n }.
    long encryptKeyServer[3] = { 13, 6397, 41989 };                                 // The key used to encrypt/decrypt server messages: { e, d, n }.
    // Possible keys: { 3, 1595, 2491 }; { 4297, 4633, 7171 }; { 13, 6397, 41989 }; { 3, 16971, 25777 };
    while (1) {                                                                     // Loop infinitely.
        error = communicateWithNewClient(s, encryptKeyCA, encryptKeyServer);        // Connect with new client and communicate over encrypted channel.
        if (error) {                                                                // If error occurred.
            closesocket(s);                                                         // Close listening socket.
            WSACleanup();                                                           // Cleanup winsock.
            return error;                                                           // Return error code.
        }
    }
    closesocket(s);                                                                 // Close listening socket.
    WSACleanup();                                                                   // Cleanup winsock.
    return 0;                                                                       // Return no error.
}


/**
 *  Sets up listening socket for TCP connection with client.
 *  Returns error code.
 */
int tcpConnect(SOCKET &s, int argc, char *argv[]) {

    int error = startWSA();                                                         // Start winsock.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    struct addrinfo *result;                                                        // Stores address info of server.
    char portNum[NI_MAXSERV];                                                       // Stores the port number of the listening socket.
    memset(&portNum, 0, NI_MAXSERV);                                                // Ensure blank.
    error = getServerAddressInfo(result, argc, argv, portNum);                      // Get address info of server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    error = createSocket(s, result);                                                // Create the socket to connect to server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    error = bindSocket(s, result);                                                  // Bind listening socket.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    freeaddrinfo(result);
    error = startListening(s, portNum);                                             // Start listening for client connections.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    return 0;                                                                       // Return no error.
}

/**
 *  Start WSA.
 *  Returns error code. 
 */
int startWSA() {

    WSADATA wsadata;                                                                // Stores WSA data.
    int error = WSAStartup(WSVERS, &wsadata);                                       // Start winsock.
    if (error != 0) {                                                               // Check for error.
        cout << "WSAStartup failed with error: " << error << endl;                  // Alert user.
        WSACleanup();                                                               // Cleanup winsock.
        return 1;                                                                   // Return error code.
    }
    if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {           // If not using correct version of winsock.
        cout << "Could not find a usable version of Winsock.dll" << endl;           // Alert user.
        WSACleanup();                                                               // Cleanup winsock.
        return 2;                                                                   // Return error code.
    }
    cout << "\nThe Winsock 2.2 dll was initialised." << endl;                       // Alert user.
    return 0;                                                                       // Return no error.
}


/**
 *  Gets this server's address info.
 *  Returns error code. 
 */
int getServerAddressInfo(struct addrinfo *&result, int argc, char *argv[], char *portNum) {

    struct addrinfo hints;                                                          // Stores hints for TCP connection setup.
    memset(&hints, 0, sizeof(struct addrinfo));                                     // Ensure blank.
    if (USE_IPV6) {                                                                 // If using IPv6.
        hints.ai_family = AF_INET6;                                                 // Use IPv6.
    } else {                                                                        // Else not using IPv6.
        hints.ai_family = AF_INET;                                                  // Use IPv4.
    }
    hints.ai_socktype = SOCK_STREAM;                                                // Use sock stream.
    hints.ai_protocol = IPPROTO_TCP;                                                // Use TCP.
    hints.ai_flags = AI_PASSIVE;                                                    // Passive listening socket.
    int iResult = 0;                                                                // Stores the result of getaddrinfo().
    if (argc == 2) {                                                                // If 2 arguments.
        iResult = getaddrinfo(NULL, argv[1], &hints, &result);                      // Get address info using port number provided by user.
        sprintf(portNum, "%s", argv[1]);                                            // Save the port number.
        cout << "\nUsing port number argv[1] = " << portNum << endl;                // Alert user.
    } else {                                                                        // Else not 2 arguments.
        cout << "\nUSAGE: server.exe [port_number]" << endl;                        // Alert user.
        iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);                 // Get address info using default port number.
        cout << "Using default settings, IP: localhost, Port: " << DEFAULT_PORT << endl;    // Alert user.
        sprintf(portNum, "%s", DEFAULT_PORT);                                       // Save the port number.
    }
    if (iResult != 0) {                                                             // If getaddrinfo executed incorrectly.
        cout << "getaddrinfo failed: " << iResult << endl;                          // Alert user.
        freeaddrinfo(result);                                                       // Free memory.
        WSACleanup();                                                               // Cleanup winsock.
        return 3;                                                                   // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Creates the socket.
 *  Returns error code. 
 */
int createSocket(SOCKET &s, struct addrinfo *result) {

    s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);        // Create socket using result of getaddrinfo().
    if (s == INVALID_SOCKET) {                                                      // If socket is still invalid.
        cout << "Error at socket(): " << WSAGetLastError() << endl;                 // Alert user.
        freeaddrinfo(result);                                                       // Free memory.
        WSACleanup();                                                               // Cleanup winsock.
        return 4;                                                                   // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Binds the socket.
 *  Returns error code. 
 */
int bindSocket(SOCKET &s, struct addrinfo *result) {
    
    int iResult = bind(s, result->ai_addr, (int)result->ai_addrlen);                // Bind socket.
    if (iResult == SOCKET_ERROR) {                                                  // If bind executed incorrectly.
        cout << "bind failed with error: " << WSAGetLastError() << endl;            // Alert user.
        freeaddrinfo(result);                                                       // Free memory.
        closesocket(s);                                                             // Close socket.
        WSACleanup();                                                               // Cleanup winsock.
        return 5;                                                                   // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Starts listening for client connections on socket.
 *  Returns error code.
 */
int startListening(SOCKET s, char *portNum) {

    if (listen(s, SOMAXCONN) == SOCKET_ERROR ) {                                    // Start listening on socket, check if executed incorrectly.
        cout << "Listen failed with error: " << WSAGetLastError() << endl;          // Alert user.
        closesocket(s);                                                             // Close socket.
        WSACleanup();                                                               // Cleanup winsock.
        return 6;                                                                   // Return error code.
    }
    cout << "\nListening at PORT: " << portNum << endl;                             // Alert user.
    return 0;                                                                       // Return no error.
}


/**
 *  Connects with a new client and communicates over encrypted channel.
 *  Returns error code.
 */
int communicateWithNewClient(SOCKET s, long *encryptKeyCA, long *encryptKeyServer) {

    cout << "\n=============================================" << endl;              // Alert user.
    cout << "Waiting for client connection..." << endl;                             // Alert user.
    SOCKET ns = INVALID_SOCKET;                                                     // The client connection socket.
    char clientHost[NI_MAXHOST];                                                    // Stores the client's IP address.
    char clientService[NI_MAXSERV];                                                 // Stores the client's port number.
    memset(&clientHost, 0, sizeof(clientHost));                                     // Ensure blank.
    memset(&clientService, 0, sizeof(clientService));                               // Ensure blank.
    int error = acceptNewClient(s, ns, clientHost, clientService);                  // Accept a new client and connect them to socket ns.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    error = simulateCASendingServerPublicKey(ns, encryptKeyCA, encryptKeyServer);   // Simulate the Certifaction Authority sending the client the public key of the server.
    if (error) {                                                                    // If error occurred.
        closesocket(ns);                                                            // Close the communication socket.
        return error;                                                               // Return error code.
    }
    long nOnce = 0;                                                                 // Stores the nOnce value, used as intial rand in CBC decryption.
    error = receiveNOnce(ns, nOnce);                                                // Receive the unencrypted nOnce value from the client.
    if (error) {                                                                    // If error occurred.
        closesocket(ns);                                                            // Close the communication socket.
        return error;                                                               // Return error code.
    }
    bool clientConnected = true;                                                    // Client is connected and communicating when true.
    while (clientConnected) {                                                       // While the client is connected.
        receiveClientMessages(ns, encryptKeyServer, nOnce, clientConnected);    // Receive encrypted messages from the client.
    }
    /*int iResult = shutdown(ns, SD_SEND);                                            // Shutdown sending and receiving over the communication socket.
    if (iResult == SOCKET_ERROR) {                                                  // If shutdown failed.
        cout << "shutdown failed with error: " << WSAGetLastError() << endl;        // Alert user.
        closesocket(ns);                                                            // Close socket.
        return 15;                                                                  // Return error code.
    }*/
    closesocket(ns);                                                                // Close the communication socket.
    cout << "\nDisconnected from client with IP address: " << clientHost;           // Alert user.
    cout << ", Port: " << clientService << endl;                                    // Alert user.
    return 0;                                                                       // Return no error.
}


/** 
 *  Accepts a new client connection and allocates the socket ns for communication.
 *  Returns error code.
 */
int acceptNewClient(SOCKET s, SOCKET &ns, char *clientHost, char *clientService) {

    struct sockaddr_storage clientAddress;                                          // Stores the client's address information.
    int addrlen = sizeof(clientAddress);                                            // Stores the size of the client's address structure.
    ns = accept(s, (struct sockaddr *)(&clientAddress), &addrlen);                  // Accept a new client connection from the listening socket to the communication socket.
    if (ns == INVALID_SOCKET) {                                                     // If accept() did not work.
        cout << "accept failed: " << WSAGetLastError() << endl;                     // Alert user.
        return 7;                                                                   // Return error code.
    } else {                                                                        // Else accept worked correctly.
        cout << "\nA client has been accepted." << endl;                            // Alert user.
        DWORD returnValue = getnameinfo((struct sockaddr *)&clientAddress, addrlen,
                                        clientHost, NI_MAXHOST,
                                        clientService, NI_MAXSERV,
                                        NI_NUMERICHOST);                            // Get the client's address information.
        if (returnValue != 0) {                                                     // If getnameinfo() returned error code.
            cout << "\nError detected: getnameinfo() failed with error #" << WSAGetLastError() << endl; // Alert user.
            return 8;                                                               // Return error code.
        } else {                                                                    // Else getnameinfo() completed without error.
            cout << "Connected to client with IP address: " << clientHost;          // Alert user.
            cout << ", at Port:" << clientService << endl;                          // Alert user.
        }
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Sends encrypted public key of server to client.
 *  Returns error code.
 */
int sendServerPublicKey(SOCKET s, long *encryptKeyCA, long *encryptKeyServer) {

    char sendBuffer[BUFFER_SIZE];                                                   // The buffer to store characters to send.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.
    sprintf(sendBuffer, "KEYS %ld %ld", encryptKeyServer[KEY_E], encryptKeyServer[KEY_N]);  // Create data to send.
    cout << "\nSimulating CA sending server's public key..." << endl;               // Alert user.
    int messageLength = strlen(sendBuffer);                                         // Get the message length.
    encryptCA(sendBuffer, messageLength, encryptKeyCA[KEY_D], encryptKeyCA[KEY_N]); // Encrypt the message.
    int error = sendMessage(s, sendBuffer, messageLength);                          // Send the message to the client.
    return error;                                                                   // Return error code if any.
}


/**
 *  Encrypt method used to encrypt the certificate authority's message.
 */
void encryptCA(char *sendBuffer, int &messageLength, int d, int n) {

    long rsaEncryptedBuffer[BUFFER_SIZE];                                           // Buffer to store RSA encrypted message.
    memset(&rsaEncryptedBuffer, 0, BUFFER_SIZE);                                    // Ensure blank.
    for (int i = 0; i < messageLength; i++) {                                       // Loop through message.
        rsaEncryptedBuffer[i] = repeatsquare(sendBuffer[i], d, n);                  // Encrypt with RSA.
    }
    createStringToSend(sendBuffer, rsaEncryptedBuffer, messageLength);              // Create string for sending to server.
}


/**
 *  Repeat Square method as found in Assignment guide.
 *  Returns encrypted long value.
 *  Magic maths occurs here.
 */
long repeatsquare(long x, long eORd, long n) {

    long y = 1;
    while (eORd > 0) {
        if ((eORd % 2) == 0) {
            x = (x * x) % n;
            eORd = eORd / 2;
        } else {
            y = (x * y) % n;
            eORd = eORd - 1;
        }
    }
    return y;
}


/**
 *  Creates a string of char representation of long values from the encrypted long buffer.
 */
void createStringToSend(char *sendBuffer, long *encryptedBuffer, int &messageLength) {

    char tempBuffer[BUFFER_SIZE];                                                   // Temporary buffer to store message.
    memset(&tempBuffer, 0, BUFFER_SIZE);                                            // Make blank.
    for (int i = 0; i < messageLength; i++) {                                       // Loop through encrypted message.
        char tempCharBuffer[BUFFER_SIZE];                                           // Stores the char representation of the long value from the encrypted buffer.
        memset(&tempCharBuffer, 0, BUFFER_SIZE);                                    // Ensure blank.
        sprintf(tempCharBuffer, "%ld", encryptedBuffer[i]);                         // Copy encrypted value from buffer into char string.
        strcat(tempBuffer, tempCharBuffer);                                         // Concatenate onto send buffer.
        strcat(tempBuffer, " ");                                                    // Space seperate values.
    }
    strcat(tempBuffer, "\r\n");                                                     // Add terminating characters to message.
    strcpy(sendBuffer, tempBuffer);                                                 // Copy message into send buffer.
    messageLength = strlen(sendBuffer);                                             // Set new message length.
}


/**
 *  Sends buffer to client.
 *  Returns error code.
 */
int sendMessage(SOCKET s, char *sendBuffer, int strlen) {

    int bytes = send(s, sendBuffer, strlen, 0);                                     // Send message to client.
    if (bytes == SOCKET_ERROR) {                                                    // If connection ended.
        cout << "send failed" << endl;                                              // Alert user.
        WSACleanup();                                                               // Cleanup winsock.
        return 9;                                                                   // Return error code.
    }
    cout << "--->";                                                                 // Show that sent message with direction of arrow.
    displayCharBuffer(sendBuffer, strlen);                                          // Alert user.
    return 0;                                                                       // Return no error.
}


/**
 *  Displays character buffer in human readable format to user.
 */
void displayCharBuffer(char *charBuffer, int messageLength) {

    for (int i = 0; i < messageLength; i++) {                                       // Loop through buffer.
        if (charBuffer[i] == '\r') {                                                // If carriage return character.
            cout << "\\r";                                                          // Output literal value.
        } else if (charBuffer[i] == '\n') {                                         // If new line character.
            cout << "\\n";                                                          // Output literal value.
        } else {                                                                    // Else normal character.
            cout << charBuffer[i];                                                  // Output character.
        }
    }
    cout << endl;                                                                   // End line.
}


/**
 *  Receives a message from the client and displays message.
 *  Returns error code.
 */
int receiveMessage(SOCKET s, char *receiveBuffer, int messageLength) {

    int i = 0;                                                                      // Index of receive buffer.
    bool messageReceived = false;                                                   // True when full message received.
    while (!messageReceived) {                                                      // Loop while message not entirely received.
        int bytes = recv(s, &receiveBuffer[i], 1, 0);                               // Receive one byte of data from the client.
        if ((bytes == SOCKET_ERROR) || (bytes == 0)) {                              // If socket error or connection ended.
            cout << "recv failed" << endl;                                          // Alert user.
            return 10;                                                              // Return error code.
        } else if (receiveBuffer[i] == '\n') {                                      // If received character is new line.
            messageReceived = true;                                                 // Full message has been received.
        } else if (i == BUFFER_SIZE) {                                              // If at buffer limit.
            cout << "Full message not received: receiveBuffer overloaded" << endl;  // Alert user.
            return 11;                                                              // Return error code.
        }
        i++;                                                                        // Increment i.
    }
    receiveBuffer[i] = '\0';                                                        // Add null terminator.
    cout << "<---";                                                                 // Show that received message with direction of arrow.
    displayCharBuffer(receiveBuffer, i);                                            // Display received message.
    removeTerminatingCharacters(receiveBuffer, i);                                  // Remove terminating characters from received message.
    messageLength = i;                                                              // Store message length.
    return 0;                                                                       // Return no error.
}


/**
 *  Removes terminating characters "\r\n" from messages.
 */
void removeTerminatingCharacters(char *charBuffer, int &messageLength) {

    messageLength -= 2;                                                             // Reduce message length by 2.
    charBuffer[messageLength] = '\0';                                               // Terminate string, removing "\r\n".
}

/**
 *  Receives message from user and compares to expected ACK string.
 *  Returns error code.
 */
int receiveACK(SOCKET s, char *expectedACK) {

    cout << "\nReceiving ACK..." << endl;                                           // Alert user.
    char receiveBuffer[BUFFER_SIZE];                                                // The buffer to store received characters.
    memset(&receiveBuffer, 0, BUFFER_SIZE);                                         // Ensure blank.
    int messageLength = 0;                                                          // Stores the length of the message, unused.
    int error = receiveMessage(s, receiveBuffer, messageLength);                    // Receive the reply from the client.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    if (strcmp(receiveBuffer, expectedACK)) {                                       // Ensure expected ACK was received.
        cout << "Something went wrong, expected ACK not received." << endl;         // Alert user.
        return 12;                                                                  // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Simulates the Certifcation Authority sending the server's public key to the client.
 *  Returns error code.
 */
int simulateCASendingServerPublicKey(SOCKET s, long *encryptKeyCA, long *encryptKeyServer) {

    int error = sendServerPublicKey(s, encryptKeyCA, encryptKeyServer);             // Send the public key to the client.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    char expectedACK[BUFFER_SIZE];                                                  // Stores the expected ACK string.
    strcpy(expectedACK, "ACK 226 public key received");                             // Create expected ACK.
    error = receiveACK(s, expectedACK);                                             // Receive ACK from client.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Receives the nOnce value from the client.
 *  Returns error code.
 */
int receiveNOnce(SOCKET s, long &nOnce) {

    cout << "\nReceiving nOnce..." << endl;                                         // Alert user.
    char receiveBuffer[BUFFER_SIZE];                                                // The buffer to store received characters.
    memset(&receiveBuffer, 0, BUFFER_SIZE);                                         // Ensure blank.
    int messageLength = 0;                                                          // Stores the length of the message.
    int error = receiveMessage(s, receiveBuffer, messageLength);                    // Receive the reply from the client.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    sscanf(receiveBuffer, "NONCE %ld", &nOnce);                                     // Extract nOnce from received message.
    cout << "\nnOnce received:\n\tnOnce = " << nOnce << endl;                       // Alert user.
    char sendBuffer[BUFFER_SIZE];                                                   // The buffer to store characters to send.
    strcpy(sendBuffer, "ACK 220 nOnce received\r\n");                               // Create the ACK to send to client.
    cout << "\nSending ACK..." << endl;                                             // Alert user.
    error = sendMessage(s, sendBuffer, strlen(sendBuffer));                         // Send ACK.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Receives encrypted message from the client, decrypts them, and replies with the decrypted message.
 *  Returns nothing as errors are treated as client disconnects.
 */
void receiveClientMessages(SOCKET s, long *encryptKeyServer, long nOnce, bool &clientConnected) {

    cout << "\n--------------------------------------------" << endl;               // Alert user.
    cout << "The server is ready to receive data." << endl;                         // Alert user.
    int error = 0;                                                                  // Stores the error code returned from functions.
    while (clientConnected) {                                                       // While client is connected.
        long encryptedBuffer[BUFFER_SIZE];                                          // The buffer to store received encrypted message.
        memset(&encryptedBuffer, 0, BUFFER_SIZE);                                   // Ensure blank.
        int messageLength = 0;                                                      // Stores the length of the received message.
        int receivedMessageLength = 0;                                              // Stores the encrypted message length.
        cout << "\nWaiting to receive encrypted message from client..." << endl;    // Alert user.
        error = receiveEncryptedMessage(s, encryptedBuffer, messageLength, receivedMessageLength);  // Receive the encrypted message.
        if (error) {                                                                // If error occurred.
            clientConnected = false;                                                // Client no longer connected.
            break;                                                                  // End while loop.
        }
        char receiveBuffer[BUFFER_SIZE];                                            // The buffer to store received characters.
        memset(&receiveBuffer, 0, BUFFER_SIZE);                                     // Ensure blank.
        cout << "\nDecrypting message..." << endl;                                  // Alert user.
        decrypt(encryptedBuffer, receiveBuffer, messageLength, encryptKeyServer[KEY_D], encryptKeyServer[KEY_N], nOnce);    // Decrypt the message using RSA and CBC.
        cout << "Decrypted message:";                                               // Alert user.
        displayCharBuffer(receiveBuffer, messageLength);                            // Alert user.
        char sendBuffer[BUFFER_SIZE];                                               // The buffer to store characters to send.
        memset(&sendBuffer, 0, BUFFER_SIZE);                                        // Ensure blank.
        sprintf(sendBuffer, "The client typed '%s' - %d bytes of information was received\r\n", receiveBuffer, receivedMessageLength);  // Create message to send.
        cout << "\nSending reply..." << endl;                                       // Alert user.
        error = sendMessage(s, sendBuffer, strlen(sendBuffer));                     // Send reply.
        if (error) {                                                                // If error occurred.
            clientConnected = false;                                                // Client no longer connected.
        }
    }
    cout << "\nClient has disconnected." << endl;                                   // Alert user.
}


/**
 *  Receives encrypted message and stores in encryptedBuffer.
 *  Returns error code.
 */
int receiveEncryptedMessage(SOCKET s, long *encryptedBuffer, int &messageLength, int &receivedMessageLength) {

    char receiveBuffer[BUFFER_SIZE];                                                // The buffer to store received characters.
    char receivedMessage[BUFFER_SIZE];                                              // Buffer to store incoming message.
    memset(receiveBuffer, 0, BUFFER_SIZE);                                          // Ensure blank.
    memset(receivedMessage, 0, BUFFER_SIZE);                                        // Ensure blank.
    memset(encryptedBuffer, 0, BUFFER_SIZE);                                        // Ensure blank.
    int bytes = 0;                                                                  // Stores the result of recv().
    int i = 0;                                                                      // The index of receivedMessage.
    bool messageReceived = false;                                                   // True when full message received.
    messageLength = 0;                                                              // The length of the encrypted buffer.
    while (!messageReceived) {                                                      // Loop through message.
        bytes = recv(s, &receivedMessage[i], 1, 0);                                 // Receive a char.
        if ((bytes == SOCKET_ERROR) || (bytes == 0)) {                              // If socket error or connection ended.
            cout << "recv failed" << endl;                                          // Alert user.
            return 13;                                                              // Return error code.
        } else if (receivedMessage[i] == '\n') {                                    // If received character is new line.
            strcat(receiveBuffer, "\r\n");                                          // Concatenate message end onto receive buffer.
            messageReceived = true;                                                 // Full message has been received.
        } else if (receivedMessage[i] == ' ') {                                     // If received character is space.
            receivedMessage[i] = '\0';                                              // Terminate string.
            sscanf(receivedMessage, "%ld ", &encryptedBuffer[messageLength]);       // Get long value from string.
            messageLength++;                                                        // Increment encrypted buffer length.
            strcat(receiveBuffer, receivedMessage);                                 // Copy received message to receive buffer (for display).
            strcat(receiveBuffer, " ");                                             // Add space.
            memset(receivedMessage, 0, BUFFER_SIZE);                                // Make received message blank again.
            i = 0;                                                                  // Reset i.
        } else if (messageLength == BUFFER_SIZE || i == BUFFER_SIZE) {              // If at buffer limit.
            cout << "Full message not received: receiveBuffer overloaded" << endl;  // Alert user.
            return 14;                                                              // Return error code.
        } else {                                                                    // Normal character.
            i++;                                                                    // Increment i.
        }
    }
    receivedMessageLength = strlen(receiveBuffer);                                  // Store the received message length.
    printBuffer("RECEIVE BUFFER", receiveBuffer, receivedMessageLength);            // Alert user.
    return 0;                                                                       // Return no error.
}


/**
 *  Napoleon's print buffer method.
 *  Outputs each byte of a char buffer in readable format with special characters displayed.
 */
void printBuffer(const char *header, char *buffer, int messageLength) {

    cout << "\n------ " << header << " ------" << endl;
    for (int i = 0; i < messageLength; i++) {
        if (buffer[i] == '\r') {
            cout << "buffer[0x";
            cout << hex << uppercase << i << "]=\\r" << endl;
        } else if (buffer[i] == '\n') {
            cout << "buffer[0x";
            cout << hex << uppercase << i << "]=\\n" << endl;
        } else {
            cout << "buffer[0x";
            cout << hex << uppercase << i << "]=" << buffer[i] << endl;
        }
    }
    cout << dec << "---" << endl;
}


/**
 *  Decrypt method used to decrypt received encrypted messages.
 */
void decrypt(long *encryptedBuffer, char *receiveBuffer, int &messageLength, int d, int n, int nOnce) {

    long rsaDecryptedBuffer[BUFFER_SIZE];                                           // Buffer to store message decrypted with RSA.
    char charBuffer[BUFFER_SIZE];                                                   // Temporary buffer to store decrypted message.
    memset(&rsaDecryptedBuffer, 0, BUFFER_SIZE);                                    // Ensure blank.
    memset(&charBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.
    for (int i = 0; i < messageLength; i++) {                                       // Loop through message.
        rsaDecryptedBuffer[i] = repeatsquare(encryptedBuffer[i], d, n);             // Decrypt with RSA.
        charBuffer[i] = cbc(rsaDecryptedBuffer[i], i == 0 ? nOnce : rsaDecryptedBuffer[i-1]);    // Decrypt with CBC.
    }
    charBuffer[messageLength] = '\0';                                               // Terminate string.
    strcpy(receiveBuffer, charBuffer);                                              // Copy decrypted string to receive buffer.
}


/**
 *  Cypher Block Chain encryption.
 *  Returns encrypted long value.
 */
long cbc(char charToEncrypt, long rand) {

    return charToEncrypt ^ rand;                                                    // Return encrypted value.
}

