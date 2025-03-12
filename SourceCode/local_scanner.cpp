#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <QString>
#include <QVBoxLayout>
#include <QProcess>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <string>
#include <QApplication>
#include <QHostAddress>
#include <QDebug>
#include "pcap.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

using namespace std;

void MainWindow::show_local()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地设备列表
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            ui->textB_ipconfig->append("Error in pcap_findalldevs: " + QString(errbuf));
            return;
        }

        // 打印可用的设备列表
            QString deviceList = "Available Network Interfaces:\n";
            for (d = alldevs; d; d = d->next)
            {
                deviceList += "\n|******** [" + QString::number(++i) + "] ********|\n" + d->name + " - " + (d->description ? d->description : "No description available") + "\n";
                deviceList += "Flags: " + QString::number(d->flags) + "\n";
                if (d->addresses) {
                    deviceList += "Addresses:\n";
                    for (pcap_addr_t *a = d->addresses; a; a = a->next)
                    {
                        if (a->addr->sa_family == AF_INET)
                        {
                            deviceList += "  IPv4 Address: " + QString(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)) + "\n";
                        } else if (a->addr->sa_family == AF_INET6)
                        {
                            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)a->addr;
                            QString ipv6Address = QHostAddress(sin6->sin6_addr.s6_addr).toString();
                            deviceList += "  IPv6 Address: " + ipv6Address + "\n";
                        }
                    }
                }
            }
        ui->textB_ipconfig->append(deviceList);

    if (i == 0)
    {
        ui->textB_ipconfig->append("No interfaces found! Make sure WinPcap/Npcap is installed.");
        return;
    }
}

void MainWindow::startCapture(int num, int amount)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum = 0;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        //ui->textB_ipconfig->append("Error in pcap_findalldevs: " + QString(errbuf));
        return;
    }

    // 打印可用的设备列表
    QString deviceList = "Available Network Interfaces:\n";
    for (d = alldevs; d; d = d->next)
    {
        deviceList += QString::number(++i) + ": " + d->name + " - " + (d->description ? d->description : "No description available") + "\n";
        ++inum;
    }
    //ui->textB_ipconfig->append(deviceList);

    if (i == 0)
    {
        //ui->textB_ipconfig->append("No interfaces found! Make sure WinPcap/Npcap is installed.");
        return;
    }

    // 选择第一个设备（可以根据需要修改选择逻辑）
    if(num > inum || num < 1 || amount < 1)
    {
        ui->textB_cap->append("选择的数字不合理\n");
        return;
    }
    inum = num;
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 打开设备
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == nullptr)
    {
        ui->textB_cap->setPlainText("Unable to open the adapter: " + QString(d->name) + " - " + QString(errbuf));
        pcap_freealldevs(alldevs);
        return;
    }

    ui->textB_cap->append("开始抓包网卡" + QString(d->name) + "\n");

    // 开始捕获数据包
    pcap_loop(adhandle, amount, packetHandler, reinterpret_cast<u_char*>(this));

    // 释放设备列表
    pcap_freealldevs(alldevs);
}

void MainWindow::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    MainWindow *window = reinterpret_cast<MainWindow*>(userData);

    // 构建数据包的十六进制字符串表示
    QString packetData;
    for (int i = 0; i < pkthdr->len; ++i)
    {
        packetData.append(QString("%1 ").arg(packet[i], 2, 16, QChar('0')).toUpper());
    }

    // 在 QTextBrowser 中打印数据包内容
    window->ui->textB_cap->append("Packet captured at length: " + QString::number(pkthdr->len));
    window->ui->textB_cap->append("Packet data: " + packetData);
}
