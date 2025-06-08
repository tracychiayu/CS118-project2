#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

int state_sec = 0;     // Current state for handshake (state of security layer)
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};  // Holds concatenated message: ClientHello || ServerHello
uint16_t ts_len = 0;

bool inc_mac = false;  // For testing only: send incorrect MACs

void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host;
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        fprintf(stderr, "Initialize Client's state_sec = CLIENT_CLIENT_HELLO_SEND\n");
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        fprintf(stderr, "Initialize Server's state_sec = SERVER_CLIENT_HELLO_AWAIT\n");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        
        tlv* ch = create_tlv(CLIENT_HELLO);  // Create ClientHello TLV
        
        uint8_t nonce[NONCE_SIZE];           // Generate Nonce
        generate_nonce(nonce, NONCE_SIZE);
        tlv* nn = create_tlv(NONCE);         // Create Nonce TLV
        add_val(nn, nonce, NONCE_SIZE);      // Copy Nonce into TLV object
        add_tlv(ch, nn);           // Add Nonce TLV into ClientHello TLV

        // Generate EC key pair (private/public)
        generate_private_key();  // 'ec_priv_key'
        derive_public_key();     // using private key 'ec_priv_key' to generate 'public_key'
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(ch, pk);

        // Serialize TLV into bytes by writing it directly to the transport layer
        uint16_t len = serialize_tlv(buf, ch);   // serialize(ch + nn + pk) -> buf
        client_hello = ch; // save for later transcript use
        ts_len = len;      // transcript length (first half)
        memcpy(ts, buf, len); // Copy serialized ClientHello into ts (transcript)

        state_sec = CLIENT_SERVER_HELLO_AWAIT;

        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        // ServerHello: Nonce + certificate + server's public key + handshake signature
        print("SEND SERVER HELLO");

        tlv* sh = create_tlv(SERVER_HELLO); // Create ServerHello TLV

        uint8_t nonce[NONCE_SIZE]; // Generate nonce
        generate_nonce(nonce, NONCE_SIZE);
        tlv* nn = create_tlv(NONCE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(sh, nn);          // Add Nonce TLV into ServerHello TLV

        load_certificate("server_cert.bin"); // Load certificate
        tlv* cert = deserialize_tlv(certificate, cert_size);  // recursively parse each TLVs: certificate(A0) -> DNS name (A1) + cert's public key (02) + signature (A2)
                                                              // signature over "DNS name + cert's public key" created using CA's public key  
        add_tlv(sh, cert);

        // Load server's private key and derive its public key
        load_private_key("server_key.bin");  // 'ec_priv_key'
        derive_public_key();                 // 'public_key'
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(sh, pk);
        
        // Create signature, TODO: Server Hello in unrecognised form
        // ServerHello(sh):
        //      SERVER HELLO TLV
        //          NONCE
        //          CERTIFICATE (DNS name, cert public key, signature over dns-name & public key)
        //          PUBLIC KEY
        //          HANDSHAKE SIGNATURE (signs all TLVs above, except itself)
        uint8_t tmp[2048];
        uint16_t ch_len = serialize_tlv(tmp, client_hello);
        uint16_t sh_len = serialize_tlv(tmp + ch_len, sh);

        // Sign everything up to this point
        uint8_t sig[72];
        size_t sig_len = sign(sig, tmp, ch_len + sh_len);   // sign ClientHello || ServerHello

        // Add signature to ServerHello
        tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig_tlv, sig, sig_len);
        add_tlv(sh, sig_tlv);

        // Serialize and cache final ServerHello
        uint16_t len = serialize_tlv(buf, sh);
        server_hello = sh;
        memcpy(ts + ts_len, buf, len);
        ts_len += len;

        // Derive symmetric key (shared secret)
        derive_secret();          // use server's 'ec_priv_key' and client's 'ec_peer_public_key'
        derive_keys(ts, ts_len);  // generate 'enc_key' & 'mac_key'

        // DEBUG
        print_tlv_bytes(buf, len);

        state_sec = SERVER_FINISHED_AWAIT;
        return len;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");

        // Compute HMAC over transcript (ts)
        uint8_t digest[32];
        unsigned int digest_len = 32;

        hmac(digest, ts, ts_len);

        // Create transcript TLV
        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, digest, digest_len);

        // Create finished TLV
        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);

        uint16_t len = serialize_tlv(buf, finished);
        if (len > max_length){
            fprintf(stderr, "Error: Finished message exceeds buffer size\n");
            exit(4);
        }

        state_sec = DATA_STATE;
        return len;
    }
    case DATA_STATE: {
        uint8_t plaintext[943];
        ssize_t input_len = input_io(plaintext, sizeof(plaintext));

        if (input_len < 0){  // No data to send
            return 0;
        }

        uint8_t iv[IV_SIZE];
        generate_nonce(iv, IV_SIZE);

        uint8_t ciphertext[944];
        size_t cipher_len = encrypt_data(iv, ciphertext, plaintext, sizeof(plaintext));

        // Calculate HMAC over IV + ciphertext
        uint8_t digest[32];
        unsigned int digest_len = 32;
        uint8_t data[2048];           // Store IV + ciphertext
        memcpy(data, iv, IV_SIZE);
        memcpy(data + IV_SIZE, ciphertext, cipher_len);
        hmac(digest, data, IV_SIZE+cipher_len);

        // Create TLVs
        tlv* t_iv = create_tlv(IV);
        add_val(t_iv, iv, IV_SIZE);

        tlv* t_cipher = create_tlv(CIPHERTEXT);
        add_val(t_cipher, ciphertext, cipher_len);

        tlv* t_mac = create_tlv(MAC);
        add_val(t_mac, digest, digest_len);

        tlv* t_data = create_tlv(DATA);
        add_tlv(t_data, t_iv);
        add_tlv(t_data, t_cipher);
        add_tlv(t_data, t_mac);

        ssize_t len = serialize_tlv(buf, t_data);

        return len;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        fprintf(stderr, "RECV CLIENT HELLO\n");

        // Parse and cache ClientHello TLV packet
        client_hello = deserialize_tlv(buf, length);
        if (!client_hello || client_hello->type != CLIENT_HELLO){ 
            fprintf(stderr, "ERROR: Receive TLV other than ClientHello\n");
            exit(6); 
        }

        // Record ClientHello into transcript
        memcpy(ts, buf, length);  
        ts_len = length;

        // Extract client's public key
        tlv* pk = get_tlv(client_hello, PUBLIC_KEY);
        if ( !pk || !pk->val || pk->length == 0){ 
            fprintf(stderr, "ERROR: Missing or invalid PUBLIC_KEY in ClientHello\n");
            exit(6); 
        }
        load_peer_public_key(pk->val, pk->length);  // 'ec_peer_public_key'

        state_sec = SERVER_SERVER_HELLO_SEND;

        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        fprintf(stderr, "RECV SERVER HELLO\n");

        // Cache ServerHello TLV packets
        server_hello = deserialize_tlv(buf, length);
        if (!server_hello){ 
            fprintf(stderr, "ERROR: Receive TLV other than ServerHello\n");
            exit(6); 
        }

        // Update transcript to ClientHello || ServerHello
        memcpy(ts + ts_len, buf, length);
        ts_len += length;

        // Extract certificate, server's public key, and signature from ServerHello
        tlv* cert = get_tlv(server_hello, CERTIFICATE);
        if (!cert || !cert->val || cert->length == 0){ 
            exit(6); 
        }

        tlv* pk = get_tlv(server_hello, PUBLIC_KEY);
        if (!pk || !pk->val || pk->length == 0){ 
            exit(6); 
        }
        

        tlv* sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);  // signature over sh + nn + cert + pk
        if (!sig || !sig->val || sig->length == 0) {
            exit(6);
        }

        // Extract DNS name, server's long term public key, and signature TLVs from certificate TLV
        tlv* dns = get_tlv(cert, DNS_NAME);
        if (!dns || !dns->val || dns->length == 0){
            exit(2);
        }

        tlv* cert_pk = get_tlv(cert, PUBLIC_KEY);
        if (!cert_pk || !cert_pk->val || cert_pk->length == 0) {
            exit(6);
        }

        tlv* cert_sig = get_tlv(cert, SIGNATURE);
        if (!cert_sig || !cert_sig->val || cert_sig->length == 0) {
            exit(1);
        }

        // Concatenate DNS name and public key into a buffer for later verification use
        uint8_t data[1024];
        size_t offset = 0;
        memcpy(data, dns->val, dns->length);
        offset += dns->length;
        memcpy(data+offset, cert_pk->val, cert_pk->length);
        offset += cert_pk->length;  // total length of concatenated data 'DNS name + public key'

        // 1. Verify the server's certificate is signed by the CA:
        // verify cert_sig with CA's public key (in "ca_public_key.bin")
        load_ca_public_key("ca_public_key.bin"); // fill out 'ec_ca_public_key'

        // int verify(const uint8_t* signature, size_t sig_size, const uint8_t* data, size_t size, EVP_PKEY* authority)
        // params: data (that signature was calculated over), size (of data), authority (ec_ca_public_key)
        // return 1 for successful verification
        if (!verify(cert_sig->val, cert_sig->length, data, offset, ec_ca_public_key)) {  
            fprintf(stderr, "Error: Certificate signature invalid\n");
            exit(1);
        }
        // 2. Check DNS name that was passed into the client's argument
        char dns_name[256] = {0};
        memcpy(dns_name, dns->val, dns->length);
        dns_name[dns->length] = '\0';     // ensures that 'dns_name' is null-terminated (required when using strcmp())

        // Compare server's DNS name with client's hostname (argv[1]) -- message did not come from the server we expected
        if (strcmp(dns_name, hostname) != 0){
            fprintf(stderr, "Error: DNS name mismatch. Expected '%s', got '%s' \n", hostname, dns_name);
            exit(2);
        }
        // 3. Verify that ServerHello is signed by the server:
        // verify sig with server's public key (ec_peer_public_key) in server's cert
        load_peer_public_key(pk->val, pk->length);
        if (!verify(sig->val, sig->length, ts, ts_len - sig->length, ec_peer_public_key)) {
            exit(3);
        }
           
        derive_secret();
        derive_keys(ts, ts_len);  // salt = ts (ClientHello || ServerHello)

        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        fprintf(stderr, "RECV FINISHED\n");

        tlv* finished = deserialize_tlv(buf, length);
        if (!finished || finished->type != FINISHED){
            fprintf(stderr, "Error: Invalid FINISHED message received\n");
            exit(4);
        }

        tlv* transcript = get_tlv(finished, TRANSCRIPT);
        if (!transcript || !transcript->val || transcript->length != 32) {
            fprintf(stderr, "Error: Missing or invalid TRANSCRIPT in FINISHED message\n");
            exit(4);
        }

        // Compute HMAC over transcript, and compare the result with the received digest of transcript TLV
        uint8_t digest[32];

        hmac(digest, ts, ts_len);
        if (memcmp(digest, transcript->val, 32) != 0){
            fprintf(stderr, "Error: Transcript HMAC does not match\n");
            exit(4);
        }


        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        tlv* t_data = deserialize_tlv(buf, length);

        tlv* t_iv = get_tlv(t_data, IV);
        tlv* t_cipher = get_tlv(t_data, CIPHERTEXT);
        tlv* t_mac = get_tlv(t_data, MAC);

        // Calculate and verify HMAC on received IV + Ciphertext
        uint8_t digest[32];
        uint8_t data[2048];           // Store received IV and ciphertext
        memcpy(data, t_iv->val, t_iv->length);
        memcpy(data + t_iv->length, t_cipher->val, t_cipher->length);
        hmac(digest, data, t_iv->length + t_cipher->length);

        if (memcmp(digest, t_mac->val, 32) != 0){
            fprintf(stderr, "Error: MAC verification failed\n");
            exit(5);
        }

        // Decrypt ciphertext to plaintext and output the data
        uint8_t plaintext[1024];
        int plain_len = decrypt_cipher(plaintext, t_cipher->val, t_cipher->length, t_iv->val);

        output_io(plaintext, plain_len);
        break;
    }
    default:
        break;
    }
}
