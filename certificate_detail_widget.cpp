#include "certificate_detail_widget.h"
#include "ui_certificate_detail_widget.h"
#include "Model/certificate.h"
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <QScrollArea>

certificate_detail_widget::certificate_detail_widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::certificate_detail_widget)
{
    ui->setupUi(this);



}

certificate_detail_widget::~certificate_detail_widget()
{
    delete ui;
}

void certificate_detail_widget::setCertificate(const Certificate* cert)
{
    if (!cert) return;

    ui->lb_version->setText("X509" + cert->getVersion());
    ui->lb_serial->setText(QString::fromStdString(cert->getSerial()));
    ui->lb_issuer->setText(QString::fromStdString(cert->getIssuer()));
    ui->lb_subject->setText(QString::fromStdString(cert->getSubject()));
    ui->lb_startday->setText(QString::fromStdString(cert->getNotBefore()));
    ui->lb_endDay->setText(QString::fromStdString(cert->getNotAfter()));
    ui->lb_pubkey->setText(cert->getPublicKeyPem());
    ui->lb_pubkeyInfo->setText(cert->getPublicKeyInfo());

    ui->lb_signatureAlgorithm->setText(cert->getSignatureAlgorithm());
    ui->lb_signatureValue->setText(cert->getSignatureHex());
}
