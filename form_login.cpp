#include "form_login.h"
#include "ui_form_login.h"
#include <QScreen>
#include <windows.h>
#include <dbt.h>
#include <QMessageBox>
#include "Model/hsmconfig.h"
#include <QSettings>
#include <QFileDialog>
Form_login::Form_login(HSMConfig* hsm, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Form_login)
{
    this->hsmconfig = hsm;
    ui->setupUi(this);
    this->setWindowTitle("Select Token For Signature");
    this->setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    this->setAttribute(Qt::WA_DeleteOnClose);

    QScreen *screen = QGuiApplication::primaryScreen();
    QRect screenGeometry = screen->availableGeometry();
    int x = (screenGeometry.width() - this->width()) / 2 + screenGeometry.x();
    int y = (screenGeometry.height() - this->height()) / 2 + screenGeometry.y();
    this->move(x, y);


    //show all token lable:

    this->checkDeviceStatus();
}


void Form_login::checkDeviceStatus()
{
    QSettings settings("config.ini", QSettings::IniFormat);
    QString libPath = settings.value("HSM/LibraryPath", QCoreApplication::applicationDirPath() + "/lib/softhsm2-x64.dll").toString();

    if (!this->hsmconfig->loadHSMLibrary(libPath))
        QMessageBox::warning(this, "Cảnh báo", "Có lỗi trong quá trình tải lên thư viện thiết bị!");

    this->hsmconfig->getAllSlotID();
    ui->comboBox->clear();
    for (int i=0; i<this->hsmconfig->allSlotID.size(); i++)
        ui->comboBox->addItem(hsmconfig->getLable(this->hsmconfig->allSlotID[i]),
                              QVariant::fromValue(this->hsmconfig->allSlotID[i]));
    ui->comboBox->setCurrentIndex(-1);
    if (this->hsmconfig->allSlotID.size() != 0) {
        ui->lb_status->setText("Đã phát hiện thiết bị khả dụng");
    } else {
        ui->lb_status->setText("Không có thiết bị");
    }
}

bool Form_login::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
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


Form_login::~Form_login()
{
    delete ui;
}

void Form_login::on_pushButton_clicked()
{
    if (ui->comboBox->currentText().trimmed()!="") {
        QVariant v = ui->comboBox->itemData(ui->comboBox->currentIndex());
        this->hsmconfig->setSlotID(static_cast<CK_SLOT_ID>(v.toULongLong()));
        emit selectOK();
        return;
    }
    QMessageBox::warning(this, "Thông báo", "Vui lòng chọn thiết bị bạn muốn sử dụng!");
}


void Form_login::on_pushButton_2_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Chọn thư viện thiết bị của bạn", "", "DLL Files (*.dll)");
    if (filePath.isEmpty())
        return;

    if (!this->hsmconfig->loadHSMLibrary(filePath)) {
        QMessageBox::critical(this, "Lỗi", "Không thể tải thư viện này!");
        return;
    }

    QSettings settings("config.ini", QSettings::IniFormat);
    settings.setValue("HSM/LibraryPath", filePath);
    settings.sync();
    this->checkDeviceStatus();
    QMessageBox::information(this, "Thành công", "Đã thay đổi thư viện thiết bị thành công!");
}

