#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QLabel>
#include <QTextBrowser>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // 设置窗口标题和标签页文本
    this->setWindowTitle("NetScan");
    ui->tabWidget->setTabText(0, "扫描主机");
    ui->tabWidget->setTabText(1, "扫描端口");
    ui->tabWidget->setTabText(2, "扫描本机");

    // 连接扫描主机和扫描端口按钮的槽函数
    connect(ui->pB_ho_start, SIGNAL(clicked()), this, SLOT(host_scan()));
    connect(ui->pB_po_start, SIGNAL(clicked()), this, SLOT(port_scan()));
    connect(ui->pB_local_start, SIGNAL(clicked()), this, SLOT(local_scan()));
    connect(ui->pB_cap_start, SIGNAL(clicked()), this, SLOT(local_cap()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

// 扫描主机的槽函数
void MainWindow::host_scan()
{
    // 获取子网地址
    QString subnet = QString("%1.%2.%3.").arg(ui->spinBox->value()).arg(ui->spinBox_2->value()).arg(ui->spinBox_3->value());
    QString temp = "扫描" + subnet + "0/24网段";

    // 设置扫描主机的文本框内容
    ui->textB_host->setPlainText(temp);
    ui->textB_host->append("该网段开放的主机：");

    // 调用主机扫描函数
    hostscan_icmp_multhr(subnet);

    ui->textB_host->append("扫描结束");
}

// 扫描端口的槽函数
void MainWindow::port_scan()
{
    ui->textB_port->clear();

    // 获取目标主机IP和端口范围
    QString ip = QString("%1.%2.%3.%4").arg(ui->spinBox_4->value()).arg(ui->spinBox_5->value()).arg(ui->spinBox_6->value()).arg(ui->spinBox_7->value());
    int pstart = ui->spinBox_8->value();
    int pend = ui->spinBox_9->value();

    // 检查端口范围是否合法
    if(pstart > pend)
    {
        QMessageBox::critical(this, "输入错误", "起始端口号大于结束端口号");
    }
    else
    {
        QString temp = "扫描:" + ip + ",端口号范围:" + QString::number(pstart) + "~" + QString::number(pend);

        // 设置扫描端口的文本框内容
        ui->textB_port->setPlainText(temp);
        ui->textB_port->append("该地址端口范围内开放的端口号：");

        // 调用端口扫描函数
        portscan_multhr(ip, pstart, pend);

        ui->textB_port->append("扫描结束");
    }
}

// 扫描本机的槽函数
void MainWindow::local_scan()
{
    ui->textB_ipconfig->clear();
    ui->textB_ipconfig->setPlainText("开始扫描本机网卡");
    show_local();
    ui->textB_ipconfig->append("扫描结束");
}

// 抓包的槽函数
void MainWindow::local_cap()
{
    ui->textB_cap->clear();
    int num = ui->spinBox_10->value();
    int amount = ui->spinBox_11->value();
    ui->textB_cap->setPlainText("开始抓包");
    startCapture(num, amount);
    ui->textB_cap->append("抓包结束");
}
