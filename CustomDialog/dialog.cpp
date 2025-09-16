#include "dialog.h"
#include "CustomDialog/ui_dialog.h"
#include <QMessageBox>

Dialog::Dialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::Dialog)
{
    ui->setupUi(this);
}

Dialog::~Dialog()
{
    delete ui;
}

QString Dialog::getCerName()
{
    return ui->cerName->text().trimmed();
}

QString Dialog::getCNName()
{
    return ui->CNName->text().trimmed();
}

QString Dialog::getOrgName()
{
    return ui->OrgName->text().trimmed();
}

QString Dialog::getCountryName()
{
    return ui->CountryName->text().trimmed();
}

int Dialog::getValiday()
{
    return ui->valiDay->text().trimmed().toInt();
}

bool Dialog::canSignCA()
{
    return ui->CerLoai->currentIndex()==0;
}

void Dialog::accept()
{
    if (ui->cerName->text().trimmed().isEmpty() || ui->CNName->text().trimmed().isEmpty() || ui->OrgName->text().trimmed().isEmpty() || ui->CountryName->text().trimmed().isEmpty() || ui->valiDay->text().trimmed().isEmpty())
    {
        QMessageBox::warning(this,"Thông báo",
                             "Không được để trống thông tin.");
        return;
    }
    if (ui->CountryName->text().trimmed().size() != 2) {
        QMessageBox::warning(this,"Thông báo",
                             "CountryName phải đúng theo tiêu chuẩn ISO 3166-1 alpha-2 (2 ký tự).");
        return;
    }

    bool ok;
    int days = ui->valiDay->text().trimmed().toInt(&ok);
    if (!ok || days <= 0) {
        QMessageBox::warning(this, "Lỗi", "ValidDay phải là một số nguyên dương!");
        return;
    }

    QDialog::accept();
}
