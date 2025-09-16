#ifndef FORM_LOGIN_H
#define FORM_LOGIN_H

#include <QWidget>
#include "Model/hsmconfig.h"
namespace Ui {
class Form_login;
}

class Form_login : public QWidget
{
    Q_OBJECT

public:
    explicit Form_login(HSMConfig* hsm, QWidget *parent = nullptr);
    ~Form_login();
    void checkDeviceStatus();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::Form_login *ui;
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;
    HSMConfig* hsmconfig;
signals:
    void selectOK();
};

#endif // FORM_LOGIN_H
