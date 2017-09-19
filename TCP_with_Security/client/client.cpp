#include "client.h"


/**
 *  The main function of the program.
 *  Returns error code.
 */
int main(int argc, char *argv[]) {

    cout << "<<< TCP (CROSS-PLATFORM, IPv6-ready) CLIENT, by Cai and Steve >>>" << endl;    // Output program title.

    SOCKET s = INVALID_SOCKET;                                                      // Initialise socket to connect to the server.
    int error = tcpConnect(s, argc, argv);                                          // Connect to server using TCP.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }

    int caKeyE = 4297;                                                              // Hardcoded certification authority public key e.
    int caKeyN = 7171;                                                              // Hardcoded certification authority public key n.
    int serverKeyE = 0;                                                             // Stores the server's public key e.
    int serverKeyN = 0;                                                             // Stores the server's public key n.
    error = receiveServerPublicKey(s, caKeyE, caKeyN, serverKeyE, serverKeyN);      // Receive the public key information for the server from the CA.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }

    long nOnce = 23;                                                                // Used as the first random number in CBC encryption.
    error = sendNOnce(s, nOnce);                                                    // Send the nOnce to the server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }

    error = sendUserMessages(s, serverKeyE, serverKeyN, nOnce);                     // Encrypts user inputted messages and sends them to the server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }

    cout << "\n--------------------------------------------" << endl;               // Alert user.
    cout << "Client is shutting down..." << endl;                                   // Alert user.
    closesocket(s);                                                                 // Close the socket.
    WSACleanup();                                                                   // Cleanup winsock.
    return 0;                                                                       // Return no error.
}


/**
 *  Setup TCP connection with server.
 *  Returns error code.
 */
int tcpConnect(SOCKET &s, int argc, char *argv[]) {

    int error = startWSA();                                                         // Start winsock.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    struct addrinfo *result;                                                        // Stores address info of server.
    memset(&result, 0, sizeof(struct addrinfo));                                    // Ensure blank.
    char portNum[NI_MAXSERV];                                                       // Stores the port number of the server.
    error = getServerAddressInfo(argc, argv, result, portNum);                      // Get address info of server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    error = createSocket(s, result);                                                // Create the socket to connect to server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    error = connectToServer(s, result, portNum);                                    // Connect socket to server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    freeaddrinfo(result);                                                           // Free memory.
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
 *  Gets the server's address info.
 *  Returns error code. 
 */
int getServerAddressInfo(int argc, char *argv[], struct addrinfo *&result, char *portNum) {

    struct addrinfo hints;                                                          // Stores hints for TCP connection setup.
    memset(&hints, 0, sizeof(struct addrinfo));                                     // Ensure blank.
    if (USE_IPV6) {                                                                 // If using IPv6.
        hints.ai_family = AF_INET6;                                                 // Use IPv6.
    } else {                                                                        // Else not using IPv6.
        hints.ai_family = AF_INET;                                                  // Use IPv4.
    }
    hints.ai_socktype = SOCK_STREAM;                                                // Use sock stream.
    hints.ai_protocol = IPPROTO_TCP;                                                // Use TCP.
    int iResult;                                                                    // Stores result of getaddrinfo().
    if (argc == 3) {                                                                // If 3 arguments.
        sprintf(portNum, "%s", argv[2]);                                            // Argument 3 is port number.
        iResult = getaddrinfo(argv[1], portNum, &hints, &result);                   // Get address info of server.
        cout << "\nUsing port number argv[1] = " << portNum << endl;                // Alert user.
    } else {                                                                        // Not 3 arguments.
        cout << "\nUSAGE: client.exe [IP_address] [port_number]" << endl;           // Alert user.
        sprintf(portNum, "%s", DEFAULT_PORT);                                       // Set port number to default.
        cout << "Using default settings, IP: localhost, Port: " << DEFAULT_PORT << endl;    // Alert user.
        iResult = getaddrinfo(NULL, portNum, &hints, &result);               // Get address info of server.
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
 *  Creates the socket for connection to server.
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
 *  Gets the name info of the server.
 *  Returns error code. 
 */
int getServerNameInfo(struct addrinfo *result, char *portNum) {

    char ipVer[80];                                                                 // Stores the IP version of the connection.
    if (result->ai_family == AF_INET) {                                             // If socket is IPv4.
        strcpy(ipVer, "IPv4");                                                      // IP version is IPv4.
    } else if (result->ai_family == AF_INET6) {                                     // Else if socket is IPv6.
        strcpy(ipVer, "IPv6");                                                      // IP version is IPv6.
    }
    DWORD returnValue;                                                              // Stores the value returned by getnameinfo().
    char serverHost[NI_MAXHOST];                                                    // Stores the server's IP address.
    char serverService[NI_MAXSERV];                                                 // Stores the server's port number.
    memset(&serverHost, 0, sizeof(serverHost));                                      // Ensure blank.
    memset(&serverService, 0, sizeof(serverService));                                // Ensure blank.
    returnValue = getnameinfo((struct sockaddr *)result->ai_addr, result->ai_addrlen,
                              serverHost, sizeof(serverHost),
                              serverService, sizeof(serverService), NI_NUMERICHOST);    // Get name info of server.
    if (returnValue != 0) {                                                         // If getnameinfo executed incorrectly.
        cout << "\nError detected: getnameinfo() failed with error# " << WSAGetLastError() << endl; // Alert user.
        freeaddrinfo(result);                                                       // Free memory.
        WSACleanup();                                                               // Cleanup winsock.
        return 6;                                                                   // Return error code.
    } else {                                                                        // Else getnameinfo executed correctly.
        cout << "Connected to server with IP address: " << serverHost;              // Alert user.
        cout << ", " << ipVer << " at port: " << portNum << endl;                   // Alert user.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Connects socket to server.
 *  Returns error code. 
 */
int connectToServer(SOCKET &s, struct addrinfo *result, char *portNum) {
    
    cout << "\nConnecting to server..." << endl;                                    // Alert user.
    if (connect(s, result->ai_addr, result->ai_addrlen) != 0) {                     // Connect socket to server and check if it executed incorrectly.
        cout << "connect failed" << endl;                                           // Alert user.
        freeaddrinfo(result);                                                       // Free memory.
        closesocket(s);                                                             // Close socket.
        WSACleanup();                                                               // Cleanup winsock.
        return 5;                                                                   // Return error code.
    }
    int error = getServerNameInfo(result, portNum);                                 // Get name info of server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Receives and stores public key of server and sends ACK reply.
 *  Returns error code.
 */
int receiveServerPublicKey(SOCKET &s, int caKeyE, int caKeyN, int &serverKeyE, int &serverKeyN) {

    int error = receiveKey(s, caKeyE, caKeyN, serverKeyE, serverKeyN);              // Receive the server's public key information.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    char sendBuffer[BUFFER_SIZE];                                                   // The buffer to store characters to send.
    strcpy(sendBuffer, "ACK 226 public key received\r\n");                          // Copy ACK message to send buffer.
    cout << "\nSending ACK..." << endl;                                             // Alert user.
    error = sendMessage(s, sendBuffer, strlen(sendBuffer));                         // Send ACK.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Receives the message containing the server's public key information.
 *  Returns error code.
 */
int receiveKey(SOCKET s, int caKeyE, int caKeyN, int &serverKeyE, int &serverKeyN) {

    long encryptedBuffer[BUFFER_SIZE];                                              // The buffer to store received encrypted message.
    memset(&encryptedBuffer, 0, BUFFER_SIZE);                                       // Ensure blank.
    int messageLength = 0;                                                          // Unused variable, stores message length of received message.
    cout << "\nReceiving server's public key from \"CA\"..." << endl;               // Alert user.
    int error = receiveEncryptedMessage(s, encryptedBuffer, messageLength);         // Receive message.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    char receiveBuffer[BUFFER_SIZE];                                                // The buffer to store received characters.
    memset(&receiveBuffer, 0, BUFFER_SIZE);                                         // Ensure blank.
    decryptCA(encryptedBuffer, receiveBuffer, messageLength, caKeyE, caKeyN);       // Decrypt message.
    sscanf(receiveBuffer, "KEYS %d %d", &serverKeyE, &serverKeyN);                  // Extract public key values from receive buffer.
    cout << dec << "\nKeys for encryption received:\n\te = " << serverKeyE << "\n\tn = " << serverKeyN << endl; // Alert user.
    return 0;                                                                       // Return no error.
}


/**
 *  Receives encrypted message and stores in encryptedBuffer.
 *  Returns error code.
 */
int receiveEncryptedMessage(SOCKET s, long *encryptedBuffer, int &messageLength) {

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
            return 7;                                                               // Return error code.
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
            return 8;                                                               // Return error code.
        } else {                                                                    // Normal character.
            i++;                                                                    // Increment i.
        }
    }
    cout << "<---";                                                                 // Alert user.
    displayCharBuffer(receiveBuffer, (int) strlen(receiveBuffer));                  // Alert user
    // printBuffer("RECEIVE BUFFER", receiveBuffer, strlen(receiveBuffer));            // DEBUG.
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
 *  Decrypt method used to decrypt received encrypted messages.
 */
void decryptCA(long *encryptedBuffer, char *receiveBuffer, int &messageLength, int e, int n) {

    char tempBuffer[BUFFER_SIZE];                                                   // Temporary buffer to store decrypted characters.
    memset(&tempBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.
    for (int i = 0; i < messageLength; i++) {                                       // Loop through message.
        tempBuffer[i] = repeatsquare(encryptedBuffer[i], e, n);                     // Decrypt with RSA.
    }
    tempBuffer[messageLength] = '\0';                                               // Terminate string.
    strcpy(receiveBuffer, tempBuffer);                                              // Copy to receive buffer.
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
 *  Sends buffer to server.
 *  Returns error code.
 */
int sendMessage(SOCKET s, char *sendBuffer, int strlen) {

    int bytes = send(s, sendBuffer, strlen, 0);                                     // Send message to server.
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
        return 10;                                                                  // Return error code.
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Receives a message from the server and displays message.
 *  Returns error code.
 */
int receiveMessage(SOCKET s, char *receiveBuffer, int messageLength) {

    int i = 0;                                                                      // Index of receive buffer.
    bool messageReceived = false;                                                   // True when full message received.
    while (!messageReceived) {                                                      // Loop while message not entirely received.
        int bytes = recv(s, &receiveBuffer[i], 1, 0);                               // Receive one byte of data from the server.
        if ((bytes == SOCKET_ERROR) || (bytes == 0)) {                              // If socket error or connection ended.
            cout << "recv failed" << endl;                                          // Alert user.
            return 7;                                                               // Return error code.
        } else if (receiveBuffer[i] == '\n') {                                      // If received character is new line.
            messageReceived = true;                                                 // Full message has been received.
        } else if (i == BUFFER_SIZE) {                                              // If at buffer limit.
            cout << "Full message not received: receiveBuffer overloaded" << endl;  // Alert user.
            return 8;                                                               // Return error code.
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
 *  Sends the nOnce to the server and waits for ACK.
 *  Returns error code.
 */
int sendNOnce(SOCKET s, long nOnce) {

    char sendBuffer[BUFFER_SIZE];                                                   // The buffer to store characters to send.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.
    sprintf(sendBuffer, "NONCE %ld", nOnce);                                        // Add nOnce to send buffer.
    strcat(sendBuffer, "\r\n");                                                     // Add terminating characters to message.
    cout << "\nSending nOnce..." << endl;                                           // Alert user.
    int error = sendMessage(s, sendBuffer, strlen(sendBuffer));                     // Send nOnce to server.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    char expectedACK[BUFFER_SIZE] = "ACK 220 nOnce received";                       // Create the expected ACK.
    error = receiveACK(s, expectedACK);                                             // Receive ACK from server.
    return error;                                                                   // Return any error code, 0 if no error.
}


/**
 *  Gets input from user and sends as encrypted message to server.
 *  Returns error code.
 */
int sendUserMessages(SOCKET s, int serverKeyE, int serverKeyN, long nOnce) {

    cout << "\n--------------------------------------------" << endl;               // Alert user.
    cout << "You may now start sending commands to the server\n\nType here:";       // Alert user.
    char sendBuffer[BUFFER_SIZE];                                                   // The buffer to store characters inputted by the user.
    memset(&sendBuffer, 0, BUFFER_SIZE);                                            // Ensure blank.
    int messageLength = 0;                                                          // Stores the length of the message.
    int error = getInput(sendBuffer, messageLength);                                // Get input from user.
    if (error) {                                                                    // If error occurred.
        return error;                                                               // Return error code.
    }
    while ((strncmp(sendBuffer, ".", 1) != 0)) {                                    // While user has not typed '.' (to exit client).
        cout << "\nEncrypting message..." << endl;                                  // Alert user.
        encrypt(sendBuffer, messageLength, serverKeyE, serverKeyN, nOnce);          // Encrypt user message.
        printBuffer("SEND BUFFER", sendBuffer, messageLength);                      // Alert user.
        cout << "\nSending encrypted message..." << endl;                           // Alert user.
        error = sendMessage(s, sendBuffer, messageLength);                          // Send message to server.
        if (error) {                                                                // If error occurred.
            return error;                                                           // Return error code.
        }

        char receiveBuffer[BUFFER_SIZE];                                            // The buffer to store received characters.
        memset(&receiveBuffer, 0, BUFFER_SIZE);                                     // Ensure blank.
        cout << "\nReceiving reply from server..." << endl;                         // Alert user.
        error = receiveMessage(s, receiveBuffer, messageLength);                    // Receive reply from server.
        if (error) {                                                                // If error occurred.
            return error;                                                           // Return error code.
        }

        memset(&sendBuffer, 0, BUFFER_SIZE);                                        // Ensure blank.
        cout << "\nReady to send another message" << endl;                          // Alert user.
        cout << "\nType here:";                                                     // Alert user.
        error = getInput(sendBuffer, messageLength);                                // Get input from user.
        if (error) {                                                                // If error occurred.
            return error;                                                           // Return error code.
        }
    }
    return 0;                                                                       // Return no error.
}


/**
 *  Gets input from user.
 *  Returns error code.
 */
int getInput(char *inputBuffer, int &messageLength) {

    if (fgets(inputBuffer, SEGMENT_SIZE, stdin) == NULL) {                          // Get input from user and store in buffer, check if executed incorrectly.
        cout << "error using fgets()" << endl;                                      // Alert user.
        return 10;                                                                  // Return error code.
    }
    messageLength = strlen(inputBuffer);                                            // Get message length.
    inputBuffer[--messageLength] = '\0';                                            // Strip '\n' from cin.
    return 0;                                                                       // Return no error.
}


/**
 *  Encrypt method used to encrypt the message to be sent.
 */
void encrypt(char *sendBuffer, int &messageLength, int e, int n, long nOnce) {

    long cbcEncryptedBuffer[BUFFER_SIZE];                                           // Buffer to store CBCed message.
    long rsaAndCBCEncryptedBuffer[BUFFER_SIZE];                                     // Buffer to store RSA encrypted message.
    memset(&cbcEncryptedBuffer, 0, BUFFER_SIZE);                                    // Ensure blank.
    memset(&rsaAndCBCEncryptedBuffer, 0, BUFFER_SIZE);                              // Ensure blank.
    for (int i = 0; i < messageLength; i++) {                                       // Loop through message.
        cbcEncryptedBuffer[i] = cbc(sendBuffer[i], i == 0 ? nOnce : cbcEncryptedBuffer[i-1]);   // Encrypt with CBC.
        rsaAndCBCEncryptedBuffer[i] = repeatsquare(cbcEncryptedBuffer[i], e, n);    // Encrypt with RSA.
    }
    createStringToSend(sendBuffer, rsaAndCBCEncryptedBuffer, messageLength);        // Create string for sending to server.
}


/**
 *  Cypher Block Chain encryption.
 *  Returns encrypted long value.
 */
long cbc(char charToEncrypt, long rand) {

    return charToEncrypt ^ rand;                                                    // Return encrypted value.
}


/**
 *  Creates a string of char representation of long values from the encrypted long buffer.
 *  Returns new message length.
 */
void createStringToSend(char *sendBuffer, long *encryptedBuffer, int &messageLength) {

    char charBuffer[BUFFER_SIZE];                                                   // Temporary character buffer to store string to send.
    memset(&charBuffer, 0, BUFFER_SIZE);                                            // Make blank.
    for (int i = 0; i < messageLength; i++) {                                       // Loop through encrypted message.
        char tempBuffer[BUFFER_SIZE];                                               // Stores the char representation of the long value from the encrypted buffer.
        memset(&tempBuffer, 0, BUFFER_SIZE);                                        // Ensure blank.
        sprintf(tempBuffer, "%ld", encryptedBuffer[i]);                             // Copy encrypted value from buffer into char string.
        strcat(charBuffer, tempBuffer);                                             // Concatenate onto send buffer.
        strcat(charBuffer, " ");                                                    // Space seperate values.
    }
    strcat(charBuffer, "\r\n");                                                     // Add terminating characters to message.
    strcpy(sendBuffer, charBuffer);                                                 // Copy the message to send buffer.
    messageLength = strlen(sendBuffer);                                             // Update message length.
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

