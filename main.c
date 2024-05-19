#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/comp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <zlib.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

#define AES_KEYLEN 32  // AES anahtar uzunluğu (256 bit)
#define AES_IVLEN 16  // AES IV uzunluğu (128 bit)
#define BUFFER_SIZE 1024
#define PACKET_TAG_SYMMETRIC_KEY_ENCRYPTED 3
#define PACKET_TAG_SIGNATURE 2
#define PACKET_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY 1
#define KEY_ID_LENGTH 8 // key_id'nin uzunluğu sabit kabul edilmiştir.
#define MAX_TIME_DIFF 300  // 5 dakika olarak ayarlanmış

// Veri ve anahtar için yapıları tanımlayalım
typedef struct {
    uint8_t tag;                         // Paket türü
    size_t length;                       // İçerik uzunluğu
    unsigned char *data;                 // Veri
} Packet;

typedef struct {
    uint8_t version;                     // İmza sürümü
    uint8_t algorithm;                   // Kullanılan şifreleme algoritması
    uint8_t key_id[KEY_ID_LENGTH];       // Göndericiye ait anahtarın ID'si
    unsigned char leading_two_octets[2]; // Mesaj özetinin ilk iki okteti
    unsigned char *signature;            // İmza verisi
    size_t sig_length;                   // İmza verisinin uzunluğu
    uint32_t timestamp;                  // İmza zaman damgası
} SignaturePacket;

// hataları bastır ve programı sonlandır 
void handleErrors(const char *error) {
    fprintf(stderr, "%s\n", error);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE); // Programı güvenli bir şekilde sonlandır
}

//RSA anahtarını dosyadan oku
RSA *read_RSA_key(const char *filename, int public) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;
    }
    RSA *rsa = public ? PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL) : PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        fprintf(stderr, "Failed to parse %s key from file %s\n", public ? "public" : "private", filename);
    }
    return rsa;
}

//mesaj dosyasını oku
unsigned char* read_text_file(const char* filename, size_t* length) {
    FILE* file = fopen(filename, "rb"); // Dosyayı ikili (binary) okuma modunda aç
    if (!file) {
        fprintf(stderr, "File cannot be opened.\n");
        return NULL;
    }

    // Dosyanın sonuna git
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file); // Dosya boyutunu al
    fseek(file, 0, SEEK_SET);     // Dosyanın başına dön

    // Dosya boyutu kadar bellek ayır
    unsigned char* buffer = (unsigned char*)malloc(file_size + 1);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(file);
        return NULL;
    }

    // Dosyayı belleğe oku
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != file_size) {
        fprintf(stderr, "Error reading file %s\n", filename);
        free(buffer);
        fclose(file);
        return NULL;
    }

    // Belleği doğru şekilde sonlandır
    buffer[file_size] = '\0'; // NULL karakteri ile sonlandır
    *length = file_size;      // Okunan verinin boyutunu döndür

    fclose(file);
    return buffer; // Bellek bloğunun adresini döndür
}

//dosya yazma işlemleri
int write_file(const char* filename, const unsigned char* data, size_t length) {
    FILE* file = fopen(filename, "wb"); // Binary modda dosyayı yazma amaçlı aç
    if (!file) {
        fprintf(stderr, "Unable to open file %s for writing.\n", filename);
        return -1;
    }

    // Dosyaya veriyi yaz
    size_t bytes_written = fwrite(data, 1, length, file);
    if (bytes_written != length) {
        fprintf(stderr, "Failed to write the full data to file %s.\n", filename);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

// Hexadecimal karakteri sayıya çevirme
int hex_char_to_int(char c) {
    if (isdigit(c)) return c - '0';
    if (isxdigit(c)) return tolower(c) - 'a' + 10;
    return -1; // Geçersiz karakter bulundu
}

// Hexadecimal string'i byte dizisine çevirme
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        int high = hex_char_to_int(hex[2 * i]);
        int low = hex_char_to_int(hex[2 * i + 1]);
        if (high == -1 || low == -1) {
            fprintf(stderr, "Invalid hex character: %c%c\n", hex[2 * i], hex[2 * i + 1]);
            return -1; // Geçersiz hexadecimal karakterler bulundu
        }
        bytes[i] = (high << 4) | low;
    }
    return 0; // Başarılı dönüşüm
}

char *base64_encode(const unsigned char *input, int length, int *out_len) {
    BIO *b64, *bio;
    BUF_MEM *bufferPtr;
    char *buff;  // Output buffer
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // bufferı temizlemek için yeni satır kullanma
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // encodelamak için datayı yaz
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    // string için bellek ayır
    buff = (char *)malloc(bufferPtr->length + 1);
    if (buff) {
        memcpy(buff, bufferPtr->data, bufferPtr->length);
        buff[bufferPtr->length] = 0;
        *out_len = bufferPtr->length;
    }

    // temizle
    BIO_free_all(bio);
    BUF_MEM_free(bufferPtr);

    return buff;
}

unsigned char *base64_decode(const unsigned char *input, int length, int *out_len) {
    BIO *b64, *bio;
    int decodeLen = calcDecodeLength(input, length);
    unsigned char *buffer = (unsigned char*)malloc(decodeLen + 1);
    if (buffer == NULL) return NULL;

    buffer[decodeLen] = '\0';

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // bufferı temizlemek için yeni satır kullanma
    bio = BIO_new_mem_buf(input, length);
    bio = BIO_push(b64, bio);

    *out_len = BIO_read(bio, buffer, length);

    BIO_free_all(bio);

    return buffer;
}

int calcDecodeLength(const unsigned char *b64input, int length) {
    int padding = 0;

    if (b64input[length-1] == '=' && b64input[length-2] == '=') //son iki karakter =
        padding = 2;
    else if (b64input[length-1] == '=') //Son karakter =
        padding = 1;

    return (int)length * 0.75 - padding;
}

// Anahtarın SHA-1 parmak izini al ve son 8 byte'ını Anahtar ID olarak kullan
int get_key_fingerprint(RSA *rsa, unsigned char *key_id) {
    unsigned char *buf = NULL;
    int len = i2d_RSAPublicKey(rsa, &buf);  // RSA_PublicKey nesnesini DER formatına dönüştür
    if (len < 0) {
        fprintf(stderr, "Failed to encode key in DER format.\n");
        return -1;
    }

    unsigned char *tmp = buf;
    unsigned char md[SHA256_DIGEST_LENGTH];
    if (!EVP_Digest(buf, len, md, NULL, EVP_sha256(), NULL)) {
        fprintf(stderr, "Failed to compute digest.\n");
        OPENSSL_free(buf);
        return -1;
    }
    OPENSSL_free(buf);

    // Anahtar ID olarak SHA-256 hash'inin son 8 baytını kullan
    memcpy(key_id, md + (SHA256_DIGEST_LENGTH - KEY_ID_LENGTH), KEY_ID_LENGTH);

    /*//Key ID yazdır
    printf("Key ID calculated: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", key_id[i]);
    }
    printf("\n");

    return 0;*/
}

// RSA özel anahtarını bulmak için yapılandırılmış bir arayüz simülasyonu
RSA* find_matching_key(const char* key_config_file, const unsigned char* key_id, size_t key_id_size, int public_key) {
    FILE* config_file = fopen(key_config_file, "r");
    if (!config_file) {
        fprintf(stderr, "Unable to open key configuration file.\n");
        return NULL;
    }

    char file_key_id[2 * KEY_ID_LENGTH + 1];  // Anahtar ID için yeterli uzunluk + null terminator
    char key_file_path[1024];
    RSA* rsa_key = NULL;

    while (fscanf(config_file, "%s %s", file_key_id, key_file_path) == 2) {
        unsigned char file_binary_key_id[KEY_ID_LENGTH];
        if (hex_to_bytes(file_key_id, file_binary_key_id, KEY_ID_LENGTH) != 0) {
            fprintf(stderr, "Invalid key ID format in configuration.\n");
            continue;
        }
        if (memcmp(key_id, file_binary_key_id, KEY_ID_LENGTH) == 0) { // Binary formatlarda kıyasla
            FILE* key_file = fopen(key_file_path, "r");
            if (!key_file) {
                fprintf(stderr, "Unable to open key file: %s\n", key_file_path);
                continue;
            }
            if (public_key) {
                rsa_key = PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL);
            } else {
                rsa_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
            }
            fclose(key_file);
            if (rsa_key) {
                break; // Eşleşen anahtar başarıyla yüklendi
            } else {
                fprintf(stderr, "Failed to load key from file: %s\n", key_file_path);
            }
        }
    }

    fclose(config_file);
    return rsa_key;
}

// İmza doğrulama
int verify_signature(const unsigned char *data, size_t data_len, const SignaturePacket *packet, RSA *rsa) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, hash);

    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, packet->signature, packet->sig_length, rsa) != 1) {
        fprintf(stderr, "Signature verification failed.\n");
        return -1;
    }
    return 0;
}

// İmza oluşturma
int create_signature(const unsigned char *data, size_t data_len, SignaturePacket *sig_packet, RSA *sender_private_key, RSA *sender_public_key) {
    // Veriyi SHA-256 ile hash'leme
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!SHA256(data, data_len, hash)) {
        fprintf(stderr, "Failed to compute SHA-256 hash.\n");
        return -1;
    }
    
    // İlk iki oktet ayarlanır.
    memcpy(sig_packet->leading_two_octets, hash, 2);

    // RSA ile imza oluştur.
    sig_packet->signature = (unsigned char *)malloc(RSA_size(sender_private_key)); // RSA imzası için yeterli alan ayırma
    if (!sig_packet->signature) {
        fprintf(stderr, "Failed to allocate memory for signature.\n");
        return -1;
    }

    // İmza işlemi.
    unsigned int sig_len;
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig_packet->signature, &sig_len, sender_private_key) != 1) {
        fprintf(stderr, "Failed to sign data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(sig_packet->signature);
        return -1;
    }

    sig_packet->sig_length = sig_len; // İmza uzunluğunu kaydet
    sig_packet->version = 4; // OpenPGP yeni format versiyonu
    sig_packet->algorithm = NID_sha256;
    get_key_fingerprint(sender_public_key, sig_packet->key_id); // RSA anahtarından Key ID hesaplama
    sig_packet->timestamp = (uint32_t)time(NULL); // Zaman damgası olarak geçerli zamanı kullan
    
    return 0;
}

//imza paketi oluştur
int create_signature_packet(const SignaturePacket *sig_packet, Packet *packet) {
    packet->tag = PACKET_TAG_SIGNATURE;

    // Paket boyutunu hesapla
    size_t total_length = KEY_ID_LENGTH + sizeof(uint32_t) + 2 + sig_packet->sig_length; // sender_key_id (8 bytes) + timestamp (4 bytes) + leading_two_octets (2 bytes) + message_digest (32 bytes)
    
    packet->data = (unsigned char *)malloc(total_length);
    if (!packet->data) {
        fprintf(stderr, "Memory allocation failed for packet data.\n");
        return -1;
    }

    // paketin datasını doldurmaya başla
    int offset = 0;
    
    // timestampi kopyala
    memcpy(packet->data + offset, &sig_packet->timestamp, sizeof(sig_packet->timestamp));
    offset += sizeof(sig_packet->timestamp);

    // Göndericinin public key ID sini kopyala
    memcpy(packet->data + offset, sig_packet->key_id, KEY_ID_LENGTH);
    offset += KEY_ID_LENGTH;

    // mesaj özetinin son iki baytını kopyala
    memcpy(packet->data + offset, sig_packet->leading_two_octets, 2);
    offset += 2;

    // bütün mesaj özetini kopyala
    memcpy(packet->data + offset, sig_packet->signature, sig_packet->sig_length);
    offset += sig_packet->sig_length;

    // paket boyutunu belirle
    packet->length = total_length;

    return 0;  // başarılı
}

//message paketi oluştur
int create_data_packet(const unsigned char *data, int data_len, const char *filename, const char *timestamp, Packet *packet) {
    // Güvenlik kontrolü, sig_packet'ın ve packet'ın geçerli olduğundan emin ol
    if (!data || !packet) {
        fprintf(stderr, "Invalid input to the function.\n");
        return -1;
    }

    // Paket başlangıcı ve metadata'nın boyutunu hesapla
    int offset = 0;
    packet->tag = PACKET_TAG_SYMMETRIC_KEY_ENCRYPTED;

    uint32_t filename_len = strlen(filename);
    uint32_t timestamp_len = strlen(timestamp);

    size_t total_length = data_len + filename_len + timestamp_len + sizeof(uint32_t) * 2; // Her string için bir uint32_t uzunluk bilgisi ekliyoruz.

    packet->data = (unsigned char *)malloc(total_length);
    if (!packet->data) {
        fprintf(stderr, "Memory allocation failed for packet data.\n");
        return -1;
    }
    
    packet->length = total_length;

    // Dosya ismi ve uzunluğunu ekle
    memcpy(packet->data + offset, &filename_len, sizeof(filename_len));
    offset += sizeof(filename_len);
    memcpy(packet->data + offset, filename, filename_len);
    offset += filename_len;

    // Zaman damgasını ve uzunluğunu ekle
    memcpy(packet->data + offset, &timestamp_len, sizeof(timestamp_len));
    offset += sizeof(timestamp_len);
    memcpy(packet->data + offset, timestamp, timestamp_len);
    offset += timestamp_len;

    // Şifrelenmiş verileri kopyala
    memcpy(packet->data + offset, data, data_len);
    offset += data_len;
    return 0;
}

//session_key_packet oluştur
int create_public_key_encrypted_session_key_packet(const unsigned char *encrypted_session_key, int encrypted_session_key_len, const unsigned char *key_id, int key_id_len, Packet *packet) {
    packet->tag = PACKET_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY;
    size_t total_length = encrypted_session_key_len + key_id_len;

    packet->data = (unsigned char *)malloc(total_length);
    if (!packet->data) {
        fprintf(stderr, "Memory allocation failed for packet data.\n");
        return -1;
    }

    packet->length = total_length;

    memcpy(packet->data, key_id, key_id_len);
    memcpy(packet->data + key_id_len, encrypted_session_key, encrypted_session_key_len);

    return 0;
}

//paketi serileştir
int serialize_packet(Packet *packet, unsigned char *output, int *output_len) {
    output[0] = 0x80 | (packet->tag & 0x3F);
    output[1] = (packet->length >> 8) & 0xFF;
    output[2] = packet->length & 0xFF;
    memcpy(output + 3, packet->data, packet->length);
    *output_len = packet->length + 3;

    /*// Log the packet content for debugging
    printf("Serialized packet content:\n");
    printf("Tag: 0x%X\n", packet->tag);
    printf("Length: %d bytes\n", packet->length);
    printf("Data: ");
    for (int i = 0; i < packet->length; i++) {
        printf("%02X ", packet->data[i]);
    }
    printf("\n");*/
    return 0;
}

//paketin serileştirilmeden önceki haline getir
int deserialize_packet(const unsigned char *serialized_data, Packet *packet) {
    if (serialized_data == NULL || packet == NULL) {
        fprintf(stderr, "Invalid input to deserialize_packet\n");
        return -1;
    }

    // Paket başlığını oku
    packet->tag = serialized_data[0];

    // Uzunluğu oku: Uzunluk big-endian olarak varsayılıyor 
    packet->length= (size_t)(serialized_data[1] << 8) | serialized_data[2];

    packet->data = (unsigned char *)malloc(packet->length);
    if (!packet->data) {
        fprintf(stderr, "Memory allocation failed for packet data.\n");
        return -1;
    }

    // Veri için hafıza ayır ve kopyala
    //packet->data = (unsigned char *)malloc(packet->length);
    if (packet->data == NULL) {
        fprintf(stderr, "Memory allocation failed in deserialize_packet\n");
        return -1;
    }

    memcpy(packet->data, serialized_data + 3, packet->length);

    return 0;
}

//verileri sıkıştır
int compress_data(unsigned char *data, int data_len, unsigned char *compressed_data, int *compressed_len) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = data_len;
    strm.next_in = data;
    strm.avail_out = data_len+BUFFER_SIZE;
    strm.next_out = compressed_data;

    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) return -1;

    if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&strm);
        return -1;
    }

    *compressed_len = data_len+BUFFER_SIZE - strm.avail_out;
    deflateEnd(&strm);
    return 0;
}

//verileri genişlet
int decompress_data(unsigned char *compressed_data, int compressed_len, unsigned char *decompressed_data, int *decompressed_len) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = compressed_len;
    strm.next_in = compressed_data;
    strm.avail_out = compressed_len+BUFFER_SIZE;  // Önceden tanımlanmış maksimum buffer boyutu
    strm.next_out = decompressed_data;

    if (inflateInit(&strm) != Z_OK) return -1;

    if (inflate(&strm, Z_FINISH) != Z_STREAM_END) {
        inflateEnd(&strm);
        return -1;
    }

    *decompressed_len = compressed_len+BUFFER_SIZE - strm.avail_out;
    inflateEnd(&strm);
    return 0;
}

//anahtarı rsa ile şifrele
int encrypt_key_with_rsa(unsigned char *aes_key, int aes_key_len, unsigned char *encrypted_key, RSA *rsa) {
    int result = RSA_public_encrypt(aes_key_len, aes_key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors("Failed to encrypt key with rsa");
    }
    return result;
}

//mesajı aes ile şifrele
int encrypt_message_with_aes(const unsigned char *plaintext, int plaintext_len,
                             const unsigned char *key, const unsigned char *iv,
                             unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Failed to create encryption EVP_CIPHER_CTX");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors("Failed to initialize encryption");

    // Bloklar halinde veriyi şifrele
    for (size_t i = 0; i < plaintext_len; i += BUFFER_SIZE) {
        size_t chunk_size = (plaintext_len - i > BUFFER_SIZE) ? BUFFER_SIZE : plaintext_len - i;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + i, chunk_size))
            handleErrors("Failed to encrypt data");
        ciphertext_len += len;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len))
        handleErrors("Failed to finalize encryption");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//mesajı şifrele
int encrypt_message(const unsigned char *plaintext, int plaintext_len,const char* filename,
                    char *final_output, int *final_output_len, RSA *sender_pub_rsa, RSA *sender_priv_rsa, RSA *receiver_pub_rsa, unsigned char *iv) {
    unsigned char aes_key[AES_KEYLEN];
    if (RAND_bytes(aes_key, AES_KEYLEN) != 1) handleErrors("Failed to genarate random aes key"); // AES anahtarını rastgele oluştur
    time_t timestamp = (uint32_t)time(NULL);

    // İmza oluştur
    SignaturePacket sig_packet;
    if (create_signature(plaintext, plaintext_len, &sig_packet, sender_priv_rsa, sender_pub_rsa) != 0) {
        fprintf(stderr, "Failed to create signature for the message.\n");
        return -1;
    }

    // Paket oluştur
    Packet data_packet, signature_packet;
    if (create_data_packet(plaintext, plaintext_len, filename, &timestamp, &data_packet) != 0 ||
        create_signature_packet(&sig_packet,&signature_packet) != 0) {
        fprintf(stderr, "Failed to create packets.\n");
        return -1;
    }
    
    // Paketleri serileştir
    unsigned char serialized_data[data_packet.length+3], serialized_signature[signature_packet.length+3];
    int data_packet_len, signature_packet_len;
    serialize_packet(&data_packet, serialized_data, &data_packet_len);
    serialize_packet(&signature_packet, serialized_signature, &signature_packet_len);

    if (data_packet_len < 0 || signature_packet_len < 0) {
    fprintf(stderr, "Failed to serialize packet.\n");
    return -1; // Serileştirme hatası durumunda işlemi durdur.
    }

    // data ve signature packetleri birleştir ve sıkıştır
    size_t combined_length = data_packet_len + signature_packet_len;
    unsigned char combined_data[combined_length];
    memcpy(combined_data, serialized_data, data_packet_len);
    memcpy(combined_data + data_packet_len, serialized_signature, signature_packet_len);

    // Veriyi sıkıştır
    unsigned char compressed_data[combined_length]; // sıkıştırılmış veri için bellekten yer ayır
    size_t compressed_length;
    if (compress_data(combined_data, combined_length, compressed_data, &compressed_length) != 0) {
        fprintf(stderr, "Failed to compress data\n");
        return -1;
    }
    
    // Sıkıştırılmış veriyi AES ile şifrele
    unsigned char encrypted_data[plaintext_len+BUFFER_SIZE];
    int encrypted_len = encrypt_message_with_aes(compressed_data, compressed_length, aes_key, iv, encrypted_data);

    // AES anahtarını RSA ile şifrele
    unsigned char *encrypted_session_key = malloc(RSA_size(receiver_pub_rsa));
    int encrypted_session_key_length = encrypt_key_with_rsa(aes_key, AES_KEYLEN, encrypted_session_key, receiver_pub_rsa);
    if (encrypted_session_key_length == -1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    Packet key_packet;
    unsigned char key_id[KEY_ID_LENGTH];
    get_key_fingerprint(receiver_pub_rsa, &key_id);

    create_public_key_encrypted_session_key_packet(encrypted_session_key, encrypted_session_key_length, &key_id, KEY_ID_LENGTH, &key_packet);
 
    // Paketleri serileştir
    unsigned char serialized_session_key_packet[BUFFER_SIZE * 4];
    int serialized_session_key_packet_len;
    serialize_packet(&key_packet, serialized_session_key_packet, &serialized_session_key_packet_len);

    if (serialized_session_key_packet_len < 0) {
    fprintf(stderr, "Failed to serialize session key packet.\n");
    return -1; // Serileştirme hatası durumunda işlemi durdur.
    }

    // her şeyi birleştir
    unsigned char final_data[encrypted_len + serialized_session_key_packet_len];
    memcpy(final_data, serialized_session_key_packet, serialized_session_key_packet_len);
    memcpy(final_data + serialized_session_key_packet_len, encrypted_data, encrypted_len);

    // Base64 encode
    char *base64 = base64_encode(final_data, encrypted_len + serialized_session_key_packet_len, final_output_len);
    //final_output=base64;
    memcpy(final_output,base64,*final_output_len);

    return 0;
}

//rsa ile anahtarın şifresini çöz
int decrypt_key_with_rsa(unsigned char *encrypted_key, int encrypted_key_len, unsigned char *key, RSA *rsa) {
    int result = RSA_private_decrypt(encrypted_key_len, encrypted_key, key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors("Failed to decrypt key with rsa");
    }
    return result;
}

//aes ile mesajın şifresini çöz
int decrypt_message_with_aes(const unsigned char *ciphertext, int ciphertext_len,
                             const unsigned char *key, const unsigned char *iv,
                             unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len = 0;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Failed to create decryption EVP_CIPHER_CTX");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors("Failed to initialize decryption");

    int update_len = 0, final_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &update_len, ciphertext, ciphertext_len))
        handleErrors("Failed to decrypt data");

    if (1 != (ret = EVP_DecryptFinal_ex(ctx, plaintext + update_len, &final_len)))
        handleErrors("Failed to finalize decryption");

    EVP_CIPHER_CTX_free(ctx);

    return update_len + final_len;
}

uint32_t bytes_to_uint32(unsigned char *bytes) {
    // Big-endian varsayarak değeri hesapla
    return (uint32_t)bytes[0] << 24 | // En anlamlı byte
           (uint32_t)bytes[1] << 16 |
           (uint32_t)bytes[2] << 8  |
           (uint32_t)bytes[3];       // En az anlamlı byte
}
void reverse_bytes(unsigned char *bytes, size_t num_bytes) {
    size_t i = 0;
    size_t j = num_bytes - 1;
    while (i < j) {
        unsigned char temp = bytes[i];
        bytes[i] = bytes[j];
        bytes[j] = temp;
        i++;
        j--;
    }
}

//mesajın şifresini çöz
int decrypt_message(const char *encrypted_message, unsigned char *plaintext,
                    int *plaintext_len, char* output_filename, RSA *priv_rsa, RSA *pub_rsa, unsigned char *iv) {
    int encoded_input_len = strlen(encrypted_message);

    // Decode from base64
    int input_len;
    unsigned char *input_data = base64_decode(encrypted_message, encoded_input_len, &input_len);
    if (input_data == NULL) {
        fprintf(stderr, "Failed to decode base64.\n");
        return -1;
    }

    // session key packeti çıkart
    Packet key_packet;
    if (deserialize_packet(input_data, &key_packet) != 0) {
        fprintf(stderr, "Failed to deserialize session key packet.\n");
        free(input_data);
        return -1;
    }

    // Key ID'yi çıkar (varsayılan olarak 8 byte olduğunu varsayalım)
    unsigned char key_id[KEY_ID_LENGTH];
    memcpy(key_id, key_packet.data, KEY_ID_LENGTH);
    
    // Şifrelenmiş anahtar verisini çıkar
    unsigned char *encrypted_key = key_packet.data + KEY_ID_LENGTH;
    int encrypted_key_len = key_packet.length - KEY_ID_LENGTH;

    // Eğer sağlanan RSA anahtar yoksa, yapılandırma dosyasından uygun anahtarı bul
    RSA *rsa_private = priv_rsa;
    if (!rsa_private) {
        rsa_private = find_matching_key("private_keyring.txt",key_id, KEY_ID_LENGTH,0);
        if (!rsa_private) {
            fprintf(stderr, "No private key matches the provided key ID or provided key is invalid.\n");
            return -1;
        }
    }

    // session keyin şifresini çöz
    unsigned char aes_key[AES_KEYLEN];
    if (decrypt_key_with_rsa(encrypted_key, encrypted_key_len, aes_key, rsa_private) != AES_KEYLEN) {
        fprintf(stderr, "Failed to decrypt session key.\n");
        free(input_data);
        return -1;
    }

    // encrypted data packeti çıkart
    unsigned char *encrypted_data = input_data + key_packet.length + 3; // Assuming correct offset calculation
    int encrypted_data_len = input_len - key_packet.length - 3; // Adjust length

    // datanın şifresini çöz
    unsigned char *compressed_data = (unsigned char *)malloc(encrypted_data_len); // Allocate memory for the compressed data
    int compressed_data_len = decrypt_message_with_aes(encrypted_data, encrypted_data_len, aes_key, iv, compressed_data);
    if (compressed_data_len < 0) {
        fprintf(stderr, "Failed to decrypt data.\n");
        free(input_data);
        free(compressed_data);
        return -1;
    }

    // datayı genişlet
    unsigned char *decompressed_data = (unsigned char *)malloc(encrypted_data_len*4);
    int decompressed_data_len;
    if (decompress_data(compressed_data, encrypted_data_len*4, decompressed_data, &decompressed_data_len) != 0) {
        fprintf(stderr, "Failed to decompress data.\n");
        free(input_data);
        free(compressed_data);
        free(decompressed_data);
        return -1;
    }

    // session signature packeti çıkart
    Packet message_packet;
    if (deserialize_packet(decompressed_data, &message_packet) != 0) {
        fprintf(stderr, "Failed to deserialize message packet.\n");
        free(input_data);
        free(compressed_data);
        free(decompressed_data);
        return -1;
    }
    
    //plaintext = message_packet.data + 17; // Assuming correct offset calculation
    unsigned char filename_len_bytes[4];
    memcpy(filename_len_bytes, message_packet.data, sizeof(filename_len_bytes));
    reverse_bytes(filename_len_bytes, sizeof(filename_len_bytes));
    unsigned int filename_len = bytes_to_uint32(filename_len_bytes);

    //output filenamei bul
    char filename[filename_len + 1];
    memcpy(filename, message_packet.data + sizeof(uint32_t), filename_len);
    filename[filename_len] = '\0'; // Null-terminate
    strcpy(output_filename, "decrypted_");
    strcat(output_filename, filename); // output filename'i decrypted_[filename] yap

    *plaintext_len = message_packet.length - filename_len - sizeof(uint32_t) * 3; // uzunluğu belirle
    memcpy(plaintext,message_packet.data + filename_len + sizeof(uint32_t) * 3,*plaintext_len);

    unsigned char *sig_data = decompressed_data + message_packet.length + 20;
    int sig_data_len = decompressed_data_len - message_packet.length - 20; // uzunluğu belirle
    
    Packet sig_data_packet;
    if (deserialize_packet(decompressed_data, &sig_data_packet) != 0) {
        fprintf(stderr, "Failed to deserialize signature packet.\n");
        return -1;
    }
    
    // İmza paketini ayıkla ve imzayı doğrula
    SignaturePacket sig_packet;
    sig_packet.signature = (unsigned char *)malloc(sig_data_len);
    memcpy(sig_packet.signature, sig_data, sig_data_len);
    sig_packet.sig_length = sig_data_len;

    memcpy(sig_packet.key_id, decompressed_data + message_packet.length + 10, KEY_ID_LENGTH);
    RSA *rsa_public = pub_rsa;
    if (!rsa_public) {
        rsa_public = find_matching_key("public_keyring.txt",sig_packet.key_id, KEY_ID_LENGTH,1);
        if (!rsa_public) {
            fprintf(stderr, "No public key matches the provided key ID or provided key is invalid.\n");
            return -1;
        }
    }

    if (verify_signature(plaintext, *plaintext_len, &sig_packet, rsa_public) != 0) {
        fprintf(stderr, "Signature verification failed\n");
        free(sig_packet.signature);
        return -1;
    }

    // Verinin SHA-256 hash'ini hesapla
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(plaintext, *plaintext_len, hash); 

    // Hash'in ilk iki oktetini al
    unsigned char leading_two_octets[2];
    memcpy(leading_two_octets, hash, 2);
    memcpy(sig_packet.leading_two_octets, decompressed_data + message_packet.length + 18, 2);
    
    // İmza paketindeki ilk iki oktetle karşılaştır
    if (memcmp(leading_two_octets, sig_packet.leading_two_octets, 2) != 0) {
        fprintf(stderr, "Hash leading two octets do not match the packet's leading two octets.\n");
        return -1;
    }

    // Zaman damgası doğrulaması
    unsigned char *timestamp = decompressed_data + message_packet.length + 6;
    reverse_bytes(timestamp, 4);
    time_t sig_time = bytes_to_uint32(timestamp);

    unsigned char *data_timestamp = message_packet.data + filename_len + sizeof(uint32_t) * 2;
    reverse_bytes(data_timestamp, 4);
    time_t data_time = bytes_to_uint32(data_timestamp);

    time_t current_time = (uint32_t)time(NULL);
    
    double seconds_diff = difftime(current_time, sig_time);
    if (seconds_diff > MAX_TIME_DIFF) {
        fprintf(stderr, "Signature timestamp is too old.\n");
        return -1;
    }
    double data_seconds_diff = difftime(current_time, data_time);
    if (data_seconds_diff > MAX_TIME_DIFF) {
        fprintf(stderr, "Message timestamp is too old.\n");
        return -1;
    }

    free(sig_packet.signature);
    free(input_data);
    free(compressed_data);
    free(decompressed_data);
    return 0;
}

int main() {
    //OpenSSL algoritmalarını çağır
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Anahtar dosya yolları
    const char *bob_public_key_filename = "pub_bob.pem";
    const char *bob_private_key_filename = "priv_bob.pem";
    const char *alice_public_key_filename = "pub_alice.pem";
    const char *alice_private_key_filename = "priv_alice.pem";

    // RSA public ve private anahtarları oku
    RSA *bob_rsa_public = read_RSA_key(bob_public_key_filename,1);
    RSA *bob_rsa_private = read_RSA_key(bob_private_key_filename,0);
    RSA *alice_rsa_public = read_RSA_key(alice_public_key_filename,1);
    RSA *alice_rsa_private = read_RSA_key(alice_private_key_filename,0);

    if (!bob_rsa_public || !bob_rsa_private || !alice_rsa_public || !alice_rsa_private) {
        fprintf(stderr, "Error loading RSA keys\n");
        RSA_free(alice_rsa_private);
        RSA_free(alice_rsa_public);
        RSA_free(bob_rsa_private);
        RSA_free(bob_rsa_public);
        return -1;
    }

    // AES için IV oluştur
    unsigned char iv[AES_IVLEN];
    if (RAND_bytes(iv, AES_IVLEN) != 1) {
        fprintf(stderr, "Error generating IV\n");
        return -1;
    }

    // Şifrelenecek metin
    const char* filename = "message.txt";
    size_t plaintext_len;
    unsigned char* plaintext = read_text_file(filename, &plaintext_len);
    if (!plaintext) {
        fprintf(stderr, "Failed to read input file.\n");
        return -1;
    }

    // Metni şifrele
    char *final_output[BUFFER_SIZE*4]; // Yeterli büyüklükte buffer
    int final_output_len;
    if (encrypt_message(plaintext, plaintext_len, filename,final_output, &final_output_len, bob_rsa_public, bob_rsa_private, alice_rsa_public, iv) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return -1;
    }

    // Şifrelenmiş veriyi bir dosyaya yaz
    const char* output_filename = "encrypted.dat";
    if (write_file(output_filename, final_output, final_output_len) != 0) {
        fprintf(stderr, "Failed to write encrypted data to file.\n");
        free(plaintext);
        return -1;
    }

    // Şifrelenmiş veriyi bir dosyadan oku
    size_t encrypted_len;
    unsigned char* encrypted_data = read_text_file(output_filename, &encrypted_len);
    if (!encrypted_data) {
        fprintf(stderr, "Failed to read encrypted input file.\n");
        return -1;
    }


    // Şifreli metni çöz
    unsigned char *decrypted_text[BUFFER_SIZE * 4];
    char Decrypted_filename[256];
    int decrypted_text_len = 0;
    //alıcının özel anahtarı (alice_rsa_private) ve gönderenin public anahtarı (bob_rsa_public) NULL verildiği için keyringden alınıyor
    if (decrypt_message(encrypted_data, decrypted_text, &decrypted_text_len, &Decrypted_filename, NULL, NULL, iv) != 0) {
        fprintf(stderr, "Decryption failed.\n");
        free(plaintext);
    }

    // çözülmüş veriyi bir dosyaya yaz
    if (write_file(Decrypted_filename, decrypted_text, decrypted_text_len) != 0) {
        fprintf(stderr, "Failed to write decrypted data to file.\n");
        free(plaintext);
        return -1;
    }

    RSA_free(alice_rsa_private);
    RSA_free(alice_rsa_public);
    RSA_free(bob_rsa_private);
    RSA_free(bob_rsa_public);
    free(plaintext);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
