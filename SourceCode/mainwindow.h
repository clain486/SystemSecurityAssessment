#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include "pcap.h"
#include <QTime>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    int hostscan_icmp_multhr(QString s);
    void sendICMPRequest(const std::string& ip);
    int hostscan_icmp(QString s);
    int portscan_multhr(QString s,int pstart,int pend);
    void show_local();
    void startCapture(int num, int amount);

private:
    Ui::MainWindow *ui;
    pcap_t *adhandle;
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

public slots:
    void host_scan();
    void port_scan();
    void local_scan();
    void local_cap();
};
#endif // MAINWINDOW_H
