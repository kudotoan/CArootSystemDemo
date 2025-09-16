#include "form_login.h"
#include <QApplication>
#include "mainwindow.h"
#include <QMessageBox>
#include "Model/hsmconfig.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    HSMConfig* hsm = new HSMConfig();
    Form_login* w = new Form_login(hsm);
    QObject::connect(w,&Form_login::selectOK,w, [=]() {
        MainWindow* mainWin = new MainWindow(hsm);
        mainWin->show();
        w->hide();
        QObject::connect(mainWin, &MainWindow::logout, mainWin, [=]() {
            hsm->closeState();
            w->show();
            w->checkDeviceStatus();
            mainWin->deleteLater();
        });
        QObject::connect(mainWin, &MainWindow::destroyed, [=]() {
        });
    });
    w->show();
    int ret = a.exec();
    delete hsm;
    return ret;
}
