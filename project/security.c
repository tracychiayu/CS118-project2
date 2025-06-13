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

        fprintf(stderr, "DEBUG: client_hello sent by client:\n");
        print_tlv_bytes(buf, len);

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
        // add_tlv(sh, nn);         // DO THIS AFTER SIGN

        load_certificate("server_cert.bin"); // Load certificate
        fprintf(stderr, "server_cert.bin:\n");
        print_tlv_bytes(certificate, cert_size);
        fprintf(stderr, "\n");
        tlv* cert = deserialize_tlv(certificate, cert_size);  // recursively parse each TLVs: certificate(A0) -> DNS name (A1) + cert's public key (02) + signature (A2)
                                                              // signature over "DNS name + cert's public key" created using CA's public key  
        // add_tlv(sh, cert);       // DO THIS AFTER SIGN 

        // Load server's private key and derive its public key
        generate_private_key();  // 'ec_priv_key'
        EVP_PKEY* ephemeral_priv_key = get_private_key();  // save the ephemeral private key before 'ec_priv_key' is overwritten
        derive_public_key();     // 'public_key'
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        // add_tlv(sh, pk);         // DO THIS AFTER SIGN 

        // TLVs so far: sh, nn, cert, pk

        // Serialize input for signing: client_hello || nn || cert || pk
        uint8_t tmp[2048];
        uint16_t sig_data_len = 0;  // signature input length
        uint16_t ch_len = serialize_tlv(tmp, client_hello);
        sig_data_len += ch_len;
        uint16_t nn_len = serialize_tlv(tmp + sig_data_len, nn);
        sig_data_len += nn_len;
        uint16_t cert_len = serialize_tlv(tmp + sig_data_len, cert);
        // memcpy(tmp+sig_data_len, certificate, cert_size);
        sig_data_len += cert_len;
        uint16_t pk_len = serialize_tlv(tmp + sig_data_len, pk);
        sig_data_len += pk_len;

        fprintf(stderr, "BEFORE SIGN:\n");
        print_tlv_bytes(tmp, sig_data_len);
        fprintf(stderr, "\n");

        // Create signature, TODO: Server Hello in unrecognised form
        // ServerHello(sh):
        //      SERVER HELLO TLV
        //          NONCE
        //          CERTIFICATE (DNS name, cert public key, signature over dns-name & public key)
        //          PUBLIC KEY
        //          HANDSHAKE SIGNATURE (signs all TLVs above, except itself)
        // uint8_t tmp[2048];
        // uint16_t ch_len = serialize_tlv(tmp, client_hello);
        // uint16_t sh_len = serialize_tlv(tmp + ch_len, sh);

        // Sign everything up to this point using private key by loading "server_key.bin"
        load_private_key("server_key.bin");  // set 'ec_priv_key'
        uint8_t sig[72];
        size_t sig_len = sign(sig, tmp, sig_data_len);   // sign client_hello || nn || cert || pk

        // Add signature to ServerHello
        tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig_tlv, sig, sig_len);
        // add_tlv(sh, sig_tlv);        // DO THIS LATER

        // Restore ephemeral key into ec_priv_key for key exchange
        set_private_key(ephemeral_priv_key);

        // Append all TLVs after Server Hello TLV, sh
        add_tlv(sh, nn);
        add_tlv(sh, cert);
        add_tlv(sh, pk);
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
        fprintf(stderr, "DEBUG: server_hello sent by server:\n");
        print_tlv_bytes(buf, len);

        state_sec = SERVER_FINISHED_AWAIT;
        return len;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");
          
        // Compute digest with transcript (ts = ClientHello || ServerHello)
        uint8_t digest[32];       // store output of hmac
        hmac(digest, ts, ts_len);

        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, digest, 32);

        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);

        uint16_t len = serialize_tlv(buf, finished);

        state_sec = DATA_STATE;
        return len;
    }
    case DATA_STATE: {
        // uint8_t plaintext[943];
        // ssize_t input_len = input_io(plaintext, sizeof(plaintext));

        // if (input_len < 0){  // No data to send
        //     return 0;
        // }

        // uint8_t iv[IV_SIZE];
        // generate_nonce(iv, IV_SIZE);

        // uint8_t ciphertext[944];
        // size_t cipher_len = encrypt_data(iv, ciphertext, plaintext, sizeof(plaintext));

        // // Calculate HMAC over IV + ciphertext
        // uint8_t digest[32];
        // unsigned int digest_len = 32;
        // uint8_t data[2048];           // Store IV + ciphertext
        // memcpy(data, iv, IV_SIZE);
        // memcpy(data + IV_SIZE, ciphertext, cipher_len);
        // hmac(digest, data, IV_SIZE+cipher_len);

        // // Create TLVs
        // tlv* t_iv = create_tlv(IV);
        // add_val(t_iv, iv, IV_SIZE);

        // tlv* t_cipher = create_tlv(CIPHERTEXT);
        // add_val(t_cipher, ciphertext, cipher_len);

        // tlv* t_mac = create_tlv(MAC);
        // add_val(t_mac, digest, digest_len);

        // tlv* t_data = create_tlv(DATA);
        // add_tlv(t_data, t_iv);
        // add_tlv(t_data, t_cipher);
        // add_tlv(t_data, t_mac);

        // ssize_t len = serialize_tlv(buf, t_data);


        return 0;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        fprintf(stderr, "RECV CLIENT HELLO\n");

        fprintf(stderr, "DEBUG: client_hello received by server:\n");
        print_tlv_bytes(buf, length);
        fprintf(stderr, "\n");

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
        return;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        fprintf(stderr, "RECV SERVER HELLO\n");
        // DEBUG
        fprintf(stderr, "DEBUG: server_hello received by client:\n");
        print_tlv_bytes(buf, length);
        fprintf(stderr, "\n");

        server_hello = deserialize_tlv(buf, length);
        if (!server_hello || server_hello->type != SERVER_HELLO){ 
            fprintf(stderr, "ERROR: Receive TLV other than ServerHello\n");
            exit(6); 
        }

        // Update transcript to ClientHello || ServerHello
        memcpy(ts + ts_len, buf, length);
        ts_len += length;

        // Extract TLVs from server_hello
        tlv* t_nn = get_tlv(server_hello, NONCE);
        tlv* t_cert = get_tlv(server_hello, CERTIFICATE);
        tlv* t_pk = get_tlv(server_hello, PUBLIC_KEY);
        tlv* t_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);

        // Parse certificate contents: DNS name, public key, signature
        tlv* t_dns = get_tlv(t_cert, DNS_NAME);
        tlv* t_cert_pk = get_tlv(t_cert, PUBLIC_KEY);
        tlv* t_cert_sig = get_tlv(t_cert, SIGNATURE);

        fprintf(stderr, "DNS name len: %d\n", t_dns->length);
        print_hex(t_dns->val, t_dns->length);
        fprintf(stderr, "Cert public key len: %d\n", t_cert_pk->length);
        print_hex(t_cert_pk->val, t_cert_pk->length);
        fprintf(stderr, "Cert sig len: %d\n", t_cert_sig->length);
        print_hex(t_cert_sig->val, t_cert_sig->length);
        fprintf(stderr, "Handshake sig len: %d\n", t_sig->length);
        print_hex(t_sig->val, t_sig->length);


        // int verify(const uint8_t* signature, size_t sig_size, const uint8_t* data, size_t size, EVP_PKEY* authority);
        // 'signature' to verify, 'sig_size': size of signature, 'data' that signature was calculated over, 'size': data length, 
        // 'authority': public key use to verify the signature ('ec_ca_public_key' or 'ec_peer_public_key')
        // return 1: success; return 0: invalid signature

        // Build the CA-signed message: A1-DNS || 02-PUBLIC KEY
        // uint8_t data[1024];
        // size_t offset = 0;
        // memcpy(data, t_dns->val, t_dns->length);
        // offset += t_dns->length;
        // memcpy(data+offset, t_cert_pk->val, t_cert_pk->length);
        // offset += t_cert_pk->length;   // offset = len(dns) + len(cert_pk)
        // fprintf(stderr, "Data of DNS + cert_pk len: %zu\n", offset);
        // print_hex(data, offset);

        // 1. Verify 't_cert_sig' with CA's public key -> exit(1) if fails
        // Build the CA-signed message: A1-DNS || 02-PUBLIC KEY
        uint8_t signed_msg[256];
        size_t signed_len = 0;

        signed_len += serialize_tlv(signed_msg, t_dns);      // A1-DNS
        signed_len += serialize_tlv(signed_msg + signed_len, t_cert_pk);  // 02-PUBLIC KEY

        load_ca_public_key("ca_public_key.bin");   // fill out 'ec_ca_public_key'
        if (!verify(t_cert_sig->val, t_cert_sig->length, signed_msg, signed_len, ec_ca_public_key)){
            fprintf(stderr, "Error: Certificate signature invalid\n");
            exit(1);
        }

        // 2. Check DNS name with hostname -> exit(2) if fails
        char dns_name[256] = {0};
        memcpy(dns_name, t_dns->val, t_dns->length);
        dns_name[t_dns->length] = '\0';
        if (strcmp(dns_name, hostname) != 0){
            fprintf(stderr, "Error: DNS name mismatch\n");
            exit(2);
        }

        // 3. Verify 't_sig' with 't_cert_pk' -> exit(2) if fails
        load_peer_public_key(t_cert_pk->val, t_cert_pk->length);   // fill out 'ec_peer_public_key'

        // Concatenate data signed by handshake signature: client_hello, nn, cert, pk
        uint8_t data2[2048];
        size_t offset2 = 0;

        offset2 += serialize_tlv(data2, client_hello);
        offset2 += serialize_tlv(data2+offset2, t_nn);
        offset2 += serialize_tlv(data2+offset2, t_cert);
        offset2 += serialize_tlv(data2+offset2, t_pk);

        if (!verify(t_sig->val, t_sig->length, data2, offset2, ec_peer_public_key)){
            fprintf(stderr, "Error: ServerHello handshake signature invalid\n");
            exit(3);
        }

        load_peer_public_key(t_pk->val, t_pk->length);  // fill out 'ec_peer_public_key'
        derive_secret();        // client's private key + server's public key
        derive_keys(ts, ts_len);  // salt = ts (ClientHello || ServerHello)  -> enc_key & mac_key

        state_sec = CLIENT_FINISHED_SEND;
        break;
        return;
    }
    case SERVER_FINISHED_AWAIT: {
        fprintf(stderr, "RECV FINISHED\n");

        tlv* finished = deserialize_tlv(buf, length);
        tlv* transcript = get_tlv(finished, TRANSCRIPT);

        // Recompute the digest with client's own transcript, then compare with server's transcript->val
        uint8_t expected_digest[32];
        hmac(expected_digest, ts, ts_len);

        if (memcmp(expected_digest, transcript->val, 32) != 0){
            fprintf(stderr, "Error: Transcript HMAC does not match\n");
            exit(4);

        }

        state_sec = DATA_STATE;
        break;
        return;
    }
    case DATA_STATE: {
        // tlv* t_data = deserialize_tlv(buf, length);

        // tlv* t_iv = get_tlv(t_data, IV);
        // tlv* t_cipher = get_tlv(t_data, CIPHERTEXT);
        // tlv* t_mac = get_tlv(t_data, MAC);

        // // Calculate and verify HMAC on received IV + Ciphertext
        // uint8_t digest[32];
        // uint8_t data[2048];           // Store received IV and ciphertext
        // memcpy(data, t_iv->val, t_iv->length);
        // memcpy(data + t_iv->length, t_cipher->val, t_cipher->length);
        // hmac(digest, data, t_iv->length + t_cipher->length);

        // if (memcmp(digest, t_mac->val, 32) != 0){
        //     fprintf(stderr, "Error: MAC verification failed\n");
        //     exit(5);
        // }

        // // Decrypt ciphertext to plaintext and output the data
        // uint8_t plaintext[1024];
        // int plain_len = decrypt_cipher(plaintext, t_cipher->val, t_cipher->length, t_iv->val);

        // output_io(plaintext, plain_len);
        break;
        return;
    }
    default:
        break;
    }
}
