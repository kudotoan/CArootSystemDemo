#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = nullptr);
    ~Dialog();
    QString getCerName();
    QString getCNName();
    QString getOrgName();
    QString getCountryName();
    int getValiday();
    bool canSignCA();

protected:
    void accept() override;

private:
    Ui::Dialog *ui;
};

#endif // DIALOG_H
