#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QStackedWidget>
#include <QWidget>
#include <QScreen>
#include <QMessageBox>
#include <windows.h>
#include <dbt.h>
#include "Model/hsmconfig.h"
#include <QFileDialog>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <QSettings>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <QInputDialog>
#include "certificate_detail_widget.h"
#include "CustomDialog/dialog.h"

MainWindow::MainWindow(HSMConfig* hsm, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    this->hsmconfig = hsm;
    ui->setupUi(this);
    this->setAttribute(Qt::WA_DeleteOnClose);
    init();
}

void MainWindow::init() {
    this->setWindowTitle("Root Certificate Manager");
    this->setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    this->setFixedSize(1024, 768);

    QScreen *screen = QGuiApplication::primaryScreen();
    QRect screenGeometry = screen->availableGeometry();
    int x = (screenGeometry.width() - this->width()) / 2 + screenGeometry.x();
    int y = (screenGeometry.height() - this->height()) / 2 + screenGeometry.y();
    this->move(x, y);
    ui->slidebar->setCurrentRow(0);
    ui->stackedWidget->setCurrentIndex(0);
    this->checkDeviceStatus();
    this->showDashboard();

    if (!this->hsmconfig->connectToSlot()) {
        QMessageBox::warning(this,"Lỗi","Có lỗi xảy ra khi mở phiên làm việc với thiết bị, vui lòng kiểm tra lại!");
    }
    this->hsmconfig->findAllCer();
    this->showSignView();
    this->showCerInforAndSettingView();

    //hide

    QSettings settings("config.ini", QSettings::IniFormat);
    QString libPath = settings.value("HSM/LibraryPath", QCoreApplication::applicationDirPath() + "/lib/softhsm2-x64.dll").toString();
    _putenv_s("PKCS11_MODULE_PATH", libPath.toStdString().c_str());
    QString providerDir = QCoreApplication::applicationDirPath() + "/lib/libp11/src";
    QString currentPath = qEnvironmentVariable("PATH");
    if (!currentPath.contains(providerDir, Qt::CaseInsensitive)) {
        QString newPath = currentPath + ";" + providerDir;
        qputenv("PATH", newPath.toUtf8());
    }
    _putenv_s("OPENSSL_MODULES",providerDir.toStdString().c_str());
    // 3. Load providers (một lần duy nhất)
    // static bool providerLoaded = false;
    // if (!providerLoaded) {
    //     if (!OSSL_PROVIDER_load(nullptr, "default")) {
    //         QMessageBox::critical(this, "Lỗi", "Không thể load provider 'default'");
    //         return;
    //     }

    //     if (!OSSL_PROVIDER_load(nullptr, "pkcs11prov")) {
    //         QMessageBox::critical(this, "Lỗi", "Không thể load provider 'pkcs11prov'");
    //         ERR_print_errors_fp(stderr);
    //         return;
    //     }
    //     providerLoaded = true;
    // }
    this->currentCSRToCer=nullptr;

}



void MainWindow::checkDeviceStatus()
{
    this->hsmconfig->getAllSlotID();
    for (int i=0; i<this->hsmconfig->allSlotID.size(); i++) {
        if (this->hsmconfig->getSlotID() == this->hsmconfig->allSlotID[i]) {
            ui->lb_status->setText("Đã kết nối");
            ui->lb_status_2->setText("Đã kết nối");
            ui->lb_status_3->setText("Đã kết nối");
            ui->lb_status_4->setText("Đã kết nối");
            return;
        }
        ui->lb_status->setText("Mất kết nối");
        ui->lb_status_2->setText("Mất kết nối");
        ui->lb_status_3->setText("Mất kết nối");
        ui->lb_status_4->setText("Mất kết nối");
    }

}

void MainWindow::hideInSignWidget()
{
    ui->label_9->hide();
    ui->pushButton_4->hide();
}

void MainWindow::resetView()
{
    this->hsmconfig->findAllCer();
    this->showSignView();
    this->showCerInforAndSettingView();
}

bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    if (eventType == "windows_generic_MSG") {
        MSG *msg = static_cast<MSG*>(message);
        if (msg->message == WM_DEVICECHANGE) {
            if (msg->wParam == DBT_DEVICEARRIVAL || msg->wParam == DBT_DEVICEREMOVECOMPLETE) {
                this->checkDeviceStatus();
            }
        }
    }
    return false;
}

void MainWindow::showDashboard()
{
    CK_TOKEN_INFO tokenInfo = hsmconfig->getInfoToken(this->hsmconfig->getSlotID());
    ui->lable_nameCA->setText(QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.label), sizeof(tokenInfo.label)).trimmed());
    ui->lable_Serial->setText(QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.serialNumber), sizeof(tokenInfo.serialNumber)).trimmed());
    ui->Lable_NSX->setText(QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.manufacturerID), sizeof(tokenInfo.manufacturerID)).trimmed());
    ui->lable_ModelDevice->setText(QString::fromUtf8(reinterpret_cast<const char*>(tokenInfo.model), sizeof(tokenInfo.model)).trimmed());
    ui->label_HardwareVersion->setText(QString("%1.%2").arg(tokenInfo.hardwareVersion.major).arg(tokenInfo.hardwareVersion.minor));
    ui->label_FirmwareVersion->setText(QString("%1.%2").arg(tokenInfo.firmwareVersion.major).arg(tokenInfo.firmwareVersion.minor));
}

void MainWindow::showSignView()
{
    QVector<Certificate> certs = this->hsmconfig->getAllCertificates();
    ui->comboBox_3->clear();
    for (int i=0; i< certs.size(); i++) {
        if (!certs[i].canSignCSR()) {
            continue;
        }
        QString idHex = QString::fromStdString(certs[i].getIdHex());
        QString label = QString::fromStdString(certs[i].getLabel());
        QString text = "ID: " + idHex + " - " + label;

        ui->comboBox_3->addItem(text, idHex);
    }
    this->hideInSignWidget();

}

void MainWindow::showCerInforAndSettingView()
{
    ui->comboBox_4->clear();
    ui->comboBox_5->clear();
    QVector<Certificate> certs = this->hsmconfig->getAllCertificates();
    for (int i=0; i< certs.size(); i++) {
        QString idHex = QString::fromStdString(certs[i].getIdHex());
        QString label = QString::fromStdString(certs[i].getLabel());
        QString text = "ID: " + idHex + " - " + label;
        ui->comboBox_4->addItem(text, idHex);
        ui->comboBox_5->addItem(text, idHex);

    }
}





MainWindow::~MainWindow()
{
    delete ui;
    if (this->currentCSRToCer) {
        delete this->currentCSRToCer;
        this->currentCSRToCer=nullptr;
    }
}

void MainWindow::on_slidebar_currentRowChanged(int currentRow)
{
    ui->stackedWidget->setCurrentIndex(currentRow);
}



void MainWindow::on_pushButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        "Chọn chứng chỉ cần ký",
        "",
        "Certificate Files (*.csr *.req *.pem);;All Files (*)"
        );
    if (filePath.isEmpty()) return;
    ui->lineEdit->setText(filePath);
}


void MainWindow::on_pushButton_2_clicked()
{
    QString csrPath = ui->lineEdit->text();
    if (csrPath.isEmpty()) {
        QMessageBox::warning(this, "Lỗi", "Vui lòng chọn file CSR trước.");
        return;
    }


    FILE* fp = nullptr;
    fopen_s(&fp, csrPath.toStdString().c_str(), "rb");
    if (!fp) {
        QMessageBox::warning(this, "Lỗi", "Không mở được file CSR.");
        return;
    }
    X509_REQ* req = PEM_read_X509_REQ(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!req) {
        QMessageBox::warning(this, "Lỗi", "Không đọc được nội dung CSR.");
        return;
    }
    // EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    // if (pkey) {
    //     BIO* bio = BIO_new(BIO_s_mem());
    //     PEM_write_bio_PUBKEY(bio, pkey);

    //     char* data;
    //     long len = BIO_get_mem_data(bio, &data);

    //     QString pubkeyPem = QString::fromUtf8(data, len);
    //     qDebug().noquote() << pubkeyPem;

    //     BIO_free(bio);
    //     EVP_PKEY_free(pkey);
    // } else {
    //     qDebug() << "No public key found in CSR.";
    // }
    // Lấy ID của certificate đang chọn
    QString selectedId = ui->comboBox_3->currentData().toString();
    QByteArray idBytes = QByteArray::fromHex(selectedId.toUtf8());
    QString encodedId = QString::fromLatin1(QUrl::toPercentEncoding(QString::fromLatin1(idBytes)));
    Certificate caCert = hsmconfig->getCertificateById(selectedId.toStdString());

    // Lấy private key tương ứng trong HSM
    QString serial = ui->lable_Serial->text();

    QString tokenLabel = hsmconfig->getLable(hsmconfig->getSlotID());
    QString keyUri = QStringLiteral("pkcs11:token=%1;serial=%2;id=%3;type=private")
                         .arg(tokenLabel, serial, encodedId);

    EVP_PKEY* caKey = hsmconfig->loadKey(keyUri);
    if (!caKey) {
        QMessageBox::warning(this, "Lỗi", "Không tải được khóa từ HSM.");
        X509_REQ_free(req);
        return;
    }

    // Ký CSR
    X509* signedCert = caCert.signCSR(req, 365, caKey);
    if (!signedCert) {
        QMessageBox::warning(this, "Lỗi", "Ký CSR thất bại.");
        EVP_PKEY_free(caKey);
        X509_REQ_free(req);
        return;
    }
    if (this->currentCSRToCer) {
        delete this->currentCSRToCer;
        this->currentCSRToCer=nullptr;
    }
    this->currentCSRToCer = new Certificate(signedCert);

    QFileInfo fileInfo(csrPath);
    QString baseName = fileInfo.completeBaseName();

    QString outPath = QFileDialog::getSaveFileName(this, "Lưu chứng chỉ đã ký", baseName + ".crt", "Certificate (*.crt *.pem)");
    if (!outPath.isEmpty()) {
        FILE* out = nullptr;
        fopen_s(&out, outPath.toStdString().c_str(), "wb");
        if (out) {
            PEM_write_X509(out, signedCert);
            fclose(out);
            QMessageBox::information(this, "Thành công", "Đã ký CSR và lưu chứng chỉ.");
        } else {
            QMessageBox::warning(this, "Lỗi", "Không thể lưu chứng chỉ.");
        }
    }
    ui->label_9->show();
    ui->pushButton_4->show();
    EVP_PKEY_free(caKey);
    X509_free(signedCert);
    X509_REQ_free(req);
}


void MainWindow::on_pushButton_4_clicked()
{
    certificate_detail_widget *widget = new certificate_detail_widget(this);
    widget->setAttribute(Qt::WA_DeleteOnClose);
    widget->setCertificate(this->currentCSRToCer);
    widget->show();
    QPushButton *q = new QPushButton("Quay lại", this);
    QVBoxLayout *layout = new QVBoxLayout(widget);
    layout->addStretch();
    layout->addWidget(q, 0, Qt::AlignCenter);
    widget->setLayout(layout);
    q->show();

    connect(q, &QPushButton::clicked, this, [q,widget]() {
        widget->hide();
        q->hide();
    });

}



void MainWindow::on_comboBox_4_currentIndexChanged(int index)
{
    QString selectedId = ui->comboBox_4->currentData().toString();
    Certificate caCert = hsmconfig->getCertificateById(selectedId.toStdString());
    ui->lb_serial->setText(caCert.getInfo());
}


void MainWindow::on_pushButton_3_clicked()
{
    QString selectedId = ui->comboBox_4->currentData().toString();
    if (selectedId.isEmpty()) return;

    Certificate caCert = hsmconfig->getCertificateById(selectedId.toStdString());

    QString dirPath = QFileDialog::getExistingDirectory(
        this,
        "Chọn thư mục lưu",
        ""
        );
    if (dirPath.isEmpty()) return;

    QString baseName = selectedId + "_PublicKey";
    QString suffix = ".pem";
    QString filePath = dirPath + QDir::separator() + baseName + suffix;

    int counter = 1;
    while (QFile::exists(filePath)) {
        filePath = dirPath + QDir::separator() + baseName + QString("%1").arg(counter, 2, 10, QChar('0')) + suffix;
        counter++;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Lỗi", "Không thể mở file để ghi!");
        return;
    }

    QTextStream out(&file);
    out << caCert.getPublicKeyPem();
    file.close();

    QMessageBox::information(this, "Hoàn tất", "Khóa đã được lưu thành công tại:\n" + filePath);
}



void MainWindow::on_pushButton_5_clicked()
{
    QString selectedId = ui->comboBox_4->currentData().toString();
    if (selectedId.isEmpty()) return;

    Certificate caCert = hsmconfig->getCertificateById(selectedId.toStdString());
    QString dirPath = QFileDialog::getExistingDirectory(
        this,
        "Chọn thư mục lưu",
        ""
        );
    if (dirPath.isEmpty()) return;

    QString baseName = selectedId + "_Certificate";
    QString suffix = ".pem";
    QString filePath = dirPath + QDir::separator() + baseName + suffix;

    int counter = 1;
    while (QFile::exists(filePath)) {
        filePath = dirPath + QDir::separator() + baseName + QString("%1").arg(counter, 2, 10, QChar('0')) + suffix;
        counter++;
    }

    if (caCert.saveCerPemToFile(filePath)) QMessageBox::information(this, "Hoàn tất", "Chứng chỉ đã được lưu thành công tại:\n" + filePath);
}


void MainWindow::on_pushButton_9_clicked()
{
    emit logout();
    this->close();
}


void MainWindow::on_pushButton_8_clicked()
{
    QString currentPin = QInputDialog::getText(this,"Nhập thông tin", "mật khẩu cũ:", QLineEdit::Password);
    if (currentPin.length()==0) return;
    QString newPin = QInputDialog::getText(this,"Nhập thông tin", "mật khẩu mới:", QLineEdit::Password);
    if (newPin.length()==0) return;
    QString newPinAgain = QInputDialog::getText(this,"Nhập thông tin", "mật khẩu mới:", QLineEdit::Password);
    if (newPinAgain.length()==0) return;
    if (newPin != newPinAgain) {
        QMessageBox::information(this, "Thông báo", "Mật khẩu mới bạn vừa nhập không khớp!");
        return;
    }
    switch (this->hsmconfig->changePin(currentPin,newPin)) {
    case 1:
        QMessageBox::information(this, "Thông báo", "Mật khẩu đã được thay đổi thành công!");
        break;
    case -1:
        QMessageBox::information(this, "Thông báo", "PKCS#11 not initialized or no session");
        break;
    case -2:
        QMessageBox::information(this, "Thông báo", "changePin: GetTokenInfo failed");
        break;
    case -3:
        QMessageBox::information(this, "Thông báo", "changePin: New PIN length invalid");
        break;
    case -4:
        QMessageBox::information(this, "Thông báo", "changePin: USER_NOT_LOGGED_IN");
        break;
    case -5:
        QMessageBox::information(this, "Thông báo", "changePin: PIN_INCORRECT");
        break;
    case -6:
        QMessageBox::information(this, "Thông báo", "changePin: PIN_LOCKED");
        break;
    case -7:
        QMessageBox::information(this, "Thông báo", "changePin: PIN_LEN_RANGE");
        break;
    default:
        QMessageBox::information(this, "Thông báo", "Có lỗi không xác định khi thay đổi mật khẩu!");
        break;
    }
}


void MainWindow::on_pushButton_7_clicked()
{
    //login if not
    if (!this->hsmconfig->isLoggedIn()) {
        std::string pin = QInputDialog::getText(this,"Đăng nhập", "Nhập mã PIN:",QLineEdit::Password).toStdString();
        if (pin=="") return;
        CK_BYTE* pinByte = (CK_BYTE*)pin.data();
        this->hsmconfig->login(pinByte);
        // for (size_t i = 0; i < pin.size(); ++i) {
        //     qDebug() << "Byte" << i << ":" << (int)pinByte[i];
        // }
    }

    //genKeyPairAndCertificate
    Dialog input(this);
    if (input.exec() == QDialog::Accepted) {
        QString cerName = input.getCerName();
        QString cn = input.getCNName();
        QString org = input.getOrgName();
        QString country = input.getCountryName();
        int days = input.getValiday();
        bool canSignCA = input.canSignCA();
        // qDebug() << cerName << " " << cn << " " << org << " " << country << " " << days << " " << canSignCA;
        int ok = this->hsmconfig->createCertificate(cerName, cn, org, country, days, canSignCA);

        if (ok == -1) {
            QMessageBox::information(this,"Thông báo!",
                                     "Thiết bị HSM không quản lý nhiều hơn 10 chứng chỉ số, vui lòng thu hồi trước khi tiếp tục!");
            return;
        } else if (!ok) {
            QMessageBox::information(this,"Thông báo!", "Có lỗi xảy ra!");
            return;
        } else {
            // qDebug() << this->hsmconfig->getAllCertificates().size();
            this->resetView();
            QMessageBox::information(this,"Thông báo!", "Đã tạo chứng chỉ thành công!");
        }
    }
}

void MainWindow::on_pushButton_6_clicked()
{
    //login if not
    if (!this->hsmconfig->isLoggedIn()) {
        std::string pin = QInputDialog::getText(this,"Đăng nhập", "Nhập mã PIN:",QLineEdit::Password).toStdString();
        if (pin=="") return;
        CK_BYTE* pinByte = (CK_BYTE*)pin.data();
        this->hsmconfig->login(pinByte);
    }
    QString selectedId = ui->comboBox_5->currentData().toString();
    if(this->hsmconfig->DestroyObject(selectedId)) {
        this->resetView();
        QMessageBox::information(this,"Thông báo!", "Đã thu hồi chứng chỉ thành công!");
        return;
    }
    QMessageBox::information(this,"Thông báo!", "Có lỗi xảy ra, thu hồi chứng chỉ thất bại!");
}

