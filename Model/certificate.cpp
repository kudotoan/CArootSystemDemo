#include "certificate.h"
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <sstream>
#include <iomanip>
#include <openssl/x509v3.h>
#include <QFile>
#include <QTextStream>
Certificate::Certificate() : cert(nullptr) {}

Certificate::Certificate(const std::vector<unsigned char>& der,
                         const std::string& lbl,
                         const std::vector<unsigned char>& _id)
    : derData(der), label(lbl), id(_id), cert(nullptr) {
    this->parseInfo();

}

Certificate::Certificate(X509* x509)
    : cert(X509_dup(x509))
{
    if (cert) {
        int len = i2d_X509(cert, nullptr);
        if (len > 0) {
            derData.resize(len);
            unsigned char* p = derData.data();
            i2d_X509(cert, &p);
        }
    }
}

Certificate::~Certificate() {
    if (cert) {
        X509_free(cert);
        cert = nullptr;
    }
}
QString Certificate::getVersion() const {
    if (!cert) return {};
    long version = X509_get_version(cert); // 0 = v1, 1 = v2, 2 = v3
    return QString("v%1").arg(version + 1);
}
QString Certificate::getSignatureAlgorithm() const {
    if (!cert) return {};

    int sig_nid = NID_undef;
    X509_get_signature_info(cert, &sig_nid, nullptr, nullptr, nullptr);

    if (sig_nid != NID_undef)
        return QString::fromUtf8(OBJ_nid2ln(sig_nid));
    return "Unknown";
}

QString Certificate::getPublicKeyInfo() const {
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return {};

    QString info;
    int keyType = EVP_PKEY_get_base_id(pkey);
    int bits = EVP_PKEY_bits(pkey);

    switch (keyType) {
    case EVP_PKEY_RSA:
        info = QString("RSA %1-bit").arg(bits);
        break;
    case EVP_PKEY_EC:
        info = QString("EC %1-bit").arg(bits);
        break;
    case EVP_PKEY_DSA:
        info = QString("DSA %1-bit").arg(bits);
        break;
    default:
        info = QString("Unknown (%1-bit)").arg(bits);
    }

    EVP_PKEY_free(pkey);
    return info;
}


QString Certificate::getKeyUsage() const {
    QStringList usages;
    ASN1_BIT_STRING* usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr);
    if (!usage) return {};

    struct Usage { int bit; const char* name; } usageList[] = {
        {KU_DIGITAL_SIGNATURE, "Digital Signature"},
        {KU_NON_REPUDIATION, "Non Repudiation"},
        {KU_KEY_ENCIPHERMENT, "Key Encipherment"},
        {KU_DATA_ENCIPHERMENT, "Data Encipherment"},
        {KU_KEY_AGREEMENT, "Key Agreement"},
        {KU_KEY_CERT_SIGN, "Key Cert Sign"},
        {KU_CRL_SIGN, "CRL Sign"}
    };

    for (auto& u : usageList) {
        if (ASN1_BIT_STRING_get_bit(usage, u.bit))
            usages << u.name;
    }

    ASN1_BIT_STRING_free(usage);
    return usages.join(", ");
}
QString Certificate::getBasicConstraints() const {
    BASIC_CONSTRAINTS* bc = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr);
    if (!bc) return {};

    QString result = bc->ca ? "CA: TRUE" : "CA: FALSE";
    BASIC_CONSTRAINTS_free(bc);
    return result;
}
QString Certificate::getSubjectKeyIdentifier() const {
    ASN1_OCTET_STRING* skid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(cert, NID_subject_key_identifier, nullptr, nullptr);
    if (!skid) return {};

    QStringList hexParts;
    for (int i = 0; i < skid->length; ++i) {
        hexParts << QString("%1").arg(skid->data[i], 2, 16, QLatin1Char('0')).toUpper();
    }

    ASN1_OCTET_STRING_free(skid);
    return hexParts.join(":");
}

QString Certificate::getSignatureHex() const {
    if (!cert) return {};

    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* sigalg = nullptr;

    X509_get0_signature(&sig, &sigalg, cert);
    if (!sig) return {};

    QString hex;
    for (int i = 0; i < sig->length; ++i) {
        hex += QString("%1").arg(sig->data[i], 2, 16, QLatin1Char('0')).toUpper();
    }

    return hex;
}


bool Certificate::parseInfo() {
    if (cert) {
        X509_free(cert);
        cert = nullptr;
    }
    const unsigned char* p = derData.data();
    cert = d2i_X509(nullptr, &p, derData.size());
    return cert != nullptr;
}

std::string Certificate::x509NameToString(X509_NAME* name) const {
    BIO* bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE);
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string Certificate::asn1TimeToString(const ASN1_TIME* time) const {
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, time);
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string Certificate::getSubject() const {
    return cert ? x509NameToString(X509_get_subject_name(cert)) : "";
}

std::string Certificate::getIssuer() const {
    return cert ? x509NameToString(X509_get_issuer_name(cert)) : "";
}

std::string Certificate::getNotBefore() const {
    return cert ? asn1TimeToString(X509_get_notBefore(cert)) : "";
}

std::string Certificate::getNotAfter() const {
    return cert ? asn1TimeToString(X509_get_notAfter(cert)) : "";
}

std::string Certificate::getSerial() const {
    if (!cert) return "";
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    return result;
}

std::string Certificate::getLabel() const {
    return label;
}

std::string Certificate::getIdHex() const {
    std::ostringstream oss;
    for (unsigned char byte : id) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}
Certificate::Certificate(const Certificate& other)
    : derData(other.derData), label(other.label), id(other.id)
{
    if (other.cert) {
        cert = X509_dup(other.cert);
    } else {
        cert = nullptr;
    }
}

Certificate& Certificate::operator=(const Certificate& other)
{
    if (this == &other) return *this;

    derData = other.derData;
    label = other.label;
    id = other.id;

    if (cert) {
        X509_free(cert);
    }

    cert = other.cert ? X509_dup(other.cert) : nullptr;
    return *this;
}

X509 *Certificate::signCSR(X509_REQ *csr, int daysValid, EVP_PKEY *caKey)
{
    if (!cert || !csr || !caKey) return nullptr;

    EVP_PKEY* csrPubKey = X509_REQ_get_pubkey(csr);
    if (!csrPubKey) {
        return nullptr;
    }

    int verify = X509_REQ_verify(csr, csrPubKey);
    EVP_PKEY_free(csrPubKey);

    if (verify != 1) {
        return nullptr;
    }
    // Tạo chứng chỉ mới
    X509* newCert = X509_new();
    if (!newCert) return nullptr;

    // Set version
    X509_set_version(newCert, 2);

    // Serial number (ngẫu nhiên)
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    BIGNUM* bn = BN_new();
    BN_rand(bn, 64, 0, 0);
    BN_to_ASN1_INTEGER(bn, serial);
    X509_set_serialNumber(newCert, serial);
    ASN1_INTEGER_free(serial);
    BN_free(bn);

    // Set issuer từ cert hiện tại (CA đang ký)
    X509_set_issuer_name(newCert, X509_get_subject_name(cert));

    // Set subject từ CSR
    X509_set_subject_name(newCert, X509_REQ_get_subject_name(csr));

    // Set public key từ CSR
    EVP_PKEY* pubkey = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(newCert, pubkey);
    EVP_PKEY_free(pubkey);

    // Set thời gian hiệu lực
    X509_gmtime_adj(X509_get_notBefore(newCert), 0);
    X509_gmtime_adj(X509_get_notAfter(newCert), 60L * 60L * 24L * daysValid);

    // Copy extensions từ CSR nếu có
    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(csr);
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
            X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
            X509_add_ext(newCert, ext, -1);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    // Add basicConstraints: CA:TRUE, pathlen:0
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, (char*)"CA:TRUE,pathlen:0");
    if (ext) {
        X509_add_ext(newCert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    // 10. Add keyUsage: keyCertSign, cRLSign
    X509_EXTENSION* ku = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, (char*)"keyCertSign,cRLSign");
    if (ku) {
        X509_add_ext(newCert, ku, -1);
        X509_EXTENSION_free(ku);
    }

    // 11. Ký bằng khóa CA
    if (!X509_sign(newCert, caKey, EVP_sha256())) {
        X509_free(newCert);
        return nullptr;
    }

    return newCert;
}

bool Certificate::canSignCSR() const
{
    if (!this->cert) return false;
    BASIC_CONSTRAINTS* bc = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    bool isCA = bc && bc->ca;
    BASIC_CONSTRAINTS_free(bc);

    if (!isCA) return false;

    ASN1_BIT_STRING* usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (!usage) return false;

    bool canSign = (usage->length > 0) && (usage->data[0] & 0x04); // 0x04 = keyCertSign
    ASN1_BIT_STRING_free(usage);

    return canSign;
}

QString Certificate::toPemString() const {
    if (!cert) return QString();

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    char* data;
    long len = BIO_get_mem_data(bio, &data);
    QString pem = QString::fromUtf8(data, static_cast<int>(len));

    BIO_free(bio);
    return pem;
}

EVP_PKEY* Certificate::getPublicKey() const {
    if (!cert) return nullptr;
    return X509_get_pubkey(cert); // caller cần free EVP_PKEY_free
}

QString Certificate::getPublicKeyPem() const {
    if (!cert) return {};

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return {};

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        EVP_PKEY_free(pkey);
        return {};
    }

    // Viết public key ra BIO ở định dạng PEM
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return {};
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    QString pemString = QString::fromUtf8(mem->data, mem->length);

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return pemString;
}

QString Certificate::getInfo() const
{
    if(!this->cert) return QString();

    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio) return QString();

    X509_print(bio, this->cert);

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    QString result = QString::fromUtf8(data, len);

    BIO_free(bio);
    return result;
}

bool Certificate::saveCerPemToFile(const QString &filePath) const
{
    if (!this->cert) return false;

    BIO* bio = BIO_new_file(filePath.toUtf8().constData(), "w");
    if (!bio) return false;

    bool ok = PEM_write_bio_X509(bio, cert);
    BIO_free(bio);

    return ok;
}


QString Certificate::getAuthorityKeyIdentifier() const {
    if (!cert) return {};

    AUTHORITY_KEYID* akid = (AUTHORITY_KEYID*)X509_get_ext_d2i(cert, NID_authority_key_identifier, nullptr, nullptr);
    if (!akid || !akid->keyid) {
        if (akid) AUTHORITY_KEYID_free(akid);
        return {};
    }

    QStringList hexParts;
    for (int i = 0; i < akid->keyid->length; ++i) {
        hexParts << QString("%1").arg(akid->keyid->data[i], 2, 16, QLatin1Char('0')).toUpper();
    }

    AUTHORITY_KEYID_free(akid);
    return hexParts.join(":");
}
