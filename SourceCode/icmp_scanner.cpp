#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <QString>
#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>

using namespace std;

mutex s_mutex2;


// ICMP 主机扫描函数
void scan_host_icmp(const string& ip, Ui::MainWindow* ui)
{
    HANDLE hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE)
    {
        cerr << "Unable to open handle." << endl;
        return;
    }

    DWORD dwRetVal = 0;
    char SendData[] = "Data Buffer";
    LPVOID ReplyBuffer = NULL;
    DWORD ReplySize = 0;

    // 分配用于接收 ICMP 响应的缓冲区
    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
    ReplyBuffer = (VOID*)malloc(ReplySize);
    if (ReplyBuffer == NULL)
    {
        cerr << "Unable to allocate memory." << endl;
        IcmpCloseHandle(hIcmpFile);
        return;
    }

    // 发送 ICMP 请求并接收响应
    dwRetVal = IcmpSendEcho(hIcmpFile, inet_addr(ip.c_str()), SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, 1400);
    if (dwRetVal != 0)
    {
        // 如果收到响应，获取响应的 IP 地址并显示
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
        struct in_addr ReplyAddr;
        ReplyAddr.S_un.S_addr = pEchoReply->Address;
        {
            // 使用互斥锁保护输出
            std::lock_guard<std::mutex> lock(s_mutex2);
            ui->textB_host->append(inet_ntoa(ReplyAddr));
            cout << "Received reply from " << inet_ntoa(ReplyAddr) << endl;
        }
    }
    else
    {
        cerr << "Failed." << endl;
    }

    // 释放缓冲区和关闭文件句柄
    free(ReplyBuffer);
    IcmpCloseHandle(hIcmpFile);
}

// ICMP 主机扫描多线程调用函数
int MainWindow::hostscan_icmp_multhr(QString s)
{
    // 初始化 Winsock 库
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
    {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }

    // 将 QString 转换为标准的 C++ 字符串类型
    string baseIp = s.toStdString();

    // 创建多个线程执行 ICMP 主机扫描
    vector<std::thread> threads;
    for (int i = 1; i <= 255; ++i)
    {
        string ip = baseIp + to_string(i);
        threads.emplace_back(scan_host_icmp, ip, ui);
    }

    // 等待所有线程执行完毕
    for (auto& thread : threads)
    {
        thread.join();
    }

    // 清理 Winsock 库
    WSACleanup();
    return 0;
}
