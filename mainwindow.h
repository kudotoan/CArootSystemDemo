#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "Model/hsmconfig.h"
#include <QTimer>
QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(HSMConfig* hsm, QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_slidebar_currentRowChanged(int currentRow);




    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_4_clicked();


    void on_comboBox_4_currentIndexChanged(int index);

    void on_pushButton_3_clicked();

    void on_pushButton_5_clicked();

    void on_pushButton_9_clicked();

    void on_pushButton_8_clicked();

    void on_pushButton_7_clicked();

    void on_pushButton_6_clicked();

protected:
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;

private:
    void showDashboard();
    void showSignView();
    void showCerInforAndSettingView();
    Ui::MainWindow *ui;
    void init();
    HSMConfig* hsmconfig;
    // QTimer *deviceCheckTimer;
    void checkDeviceStatus();
    QString tokenLable;
    void hideInSignWidget();
    Certificate* currentCSRToCer;
    void resetView();

signals:
    void logout();
};
#endif // MAINWINDOW_H
