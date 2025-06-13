# Secure Client-Server Handshake - README

## Design Choices

I followed the TLV-based message structure for each step in the handshake. Each message (ClientHello, ServerHello) was serialized into a flat byte stream, with nested TLVs representing key fields like nonce, public key, certificate, and signatures. I structured the handshake to follow this order: ClientHello -> ServerHello -> Finished, with transcript-based MAC verification to ensure integrity. I reused existing helper functions like `generate_private_key`, `sign`, and `verify`, and separated ephemeral keys from long-term keys using `set_private_key`.

## Problems Encountered

One of the biggest challenges was understanding how to construct and verify the certificate signature correctly. At first, I tried verifying the certificate by extracting and concatenating only the raw values of the DNS name and public key, but the signature verification kept failing. It turned out the CA signed the **entire TLVs**, not just the values, so I had to serialize and concatenate the full DNS and public key TLVs to compute the correct digest.

Another issue was managing ephemeral key state: calling `load_private_key("server_key.bin")` temporarily overwrote the ephemeral key needed later for key exchange. I solved this by caching the ephemeral key with `get_private_key()` and restoring it with `set_private_key()` after signing the handshake.

Finally, I also ran into bugs where the client received corrupted or malformed TLVs, mostly due to reusing shared buffers or freeing memory too early. I fixed this by carefully managing memory, using `memcpy`, and debugging using `print_tlv_bytes`.

## Summary

Most issues were around careful serialization and TLV structure awareness. After sorting out the signature verification logic and buffer handling, the handshake and mutual authentication worked as expected.
