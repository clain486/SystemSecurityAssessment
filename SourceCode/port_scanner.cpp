#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <winsock2.h>
#include <QString>
#include "mainwindow.h"
#include "ui_mainwindow.h"

using namespace std;

// 定义常量
constexpr int THREAD_NUM = 200;  // 线程数
constexpr int PORT_BEGIN = 1;    // 起始端口号
constexpr int PORT_END = 65535;  // 结束端口号

// 定义全局变量和互斥锁
mutex s_mutex;
atomic<int> s_port;
QList<int> open_port;

// 端口扫描函数
void scan_port(const string& ip, int pstart, int pend)
{
    // 初始化端口号
    s_port = max(PORT_BEGIN, pstart);
    while (true)
    {
        int port = s_port++;
        // 检查端口号是否超出范围
        if (port > PORT_END || port > pend)
            break;

        // 创建套接字并设置非阻塞模式
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET)
        {
            continue;
        }
        u_long mode = 1;
        if (ioctlsocket(s, FIONBIO, &mode) == SOCKET_ERROR)
        {
            closesocket(s);
            continue;
        }

        // 尝试连接端口
        int result = connect(s, (sockaddr*)&addr, sizeof(addr));
        if (result == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            // 检查错误码，忽略阻塞和进行中的连接
            if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS)
            {
                closesocket(s);
                continue;
            }
        }
        else if (result == 0)
        {
            // 如果连接成功，记录开放的端口
            std::lock_guard<std::mutex> lock(s_mutex);
            if (port >= pstart)
            {
                cout << "Port " << port << " is open." << endl;
                open_port.append(port);
            }
        }

        // 使用 select 函数检查套接字状态
        fd_set writefds{};
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);
        timeval timeout{};
        timeout.tv_sec = 1;  // 设置超时时间为1秒
        timeout.tv_usec = 0;
        result = select(0, nullptr, &writefds, nullptr, &timeout);
        if (result == SOCKET_ERROR)
        {
            closesocket(s);
            continue;
        } else if (result == 0)
        {
            closesocket(s);
            continue;
        }

        // 记录开放的端口
        std::lock_guard<std::mutex> lock(s_mutex);
        cout << "Port " << port << " is open." << endl;
        open_port.append(port);
        closesocket(s);
    }
}

// 多线程端口扫描函数
int MainWindow::portscan_multhr(QString s, int pstart, int pend)
{
    WSADATA wsaData{};
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    open_port.clear();
    if (err != 0)
    {
        cerr << "WSAStartup failed with error: " << err << endl;
        return -1;
    }

    // 获取目标IP地址
    string ip = s.toStdString();

    // 创建线程执行端口扫描
    std::thread threads[THREAD_NUM];
    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i] = std::thread(scan_port, ip, pstart, pend);
    }

    // 等待所有线程执行完毕
    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i].join();
    }

    // 清理 Winsock
    WSACleanup();

    // 将开放的端口信息显示在界面上
    for (int i = 0; i < open_port.size(); i++)
    {
        ui->textB_port->append(QString::number(open_port[i]));
    }
    return 0;
}
