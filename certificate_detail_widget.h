#ifndef CERTIFICATE_DETAIL_WIDGET_H
#define CERTIFICATE_DETAIL_WIDGET_H

#include <QWidget>

namespace Ui {
class certificate_detail_widget;
}

class Certificate; // forward declare

class certificate_detail_widget : public QWidget
{
    Q_OBJECT

public:
    explicit certificate_detail_widget(QWidget *parent = nullptr);
    ~certificate_detail_widget();

    void setCertificate(const Certificate* cert);

private:
    Ui::certificate_detail_widget *ui;
};

#endif // CERTIFICATE_DETAIL_WIDGET_H
