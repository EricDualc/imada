#include "imadanodeconfigdialog.h"
#include "ui_imadanodeconfigdialog.h"

#include <QModelIndex>

ImadaNodeConfigDialog::ImadaNodeConfigDialog(QWidget *parent, QString nodeAddress, QString privkey) :
    QDialog(parent),
    ui(new Ui::ImadaNodeConfigDialog)
{
    ui->setupUi(this);
    QString desc = "rpcallowip=127.0.0.1<br>rpcuser=REPLACEME<br>rpcpassword=REPLACEME<br>staking=0<br>server=1<br>listen=1<br>port=REPLACEMEWITHYOURPORT<br>masternode=1<br>masternodeaddr=" + nodeAddress + "<br>masternodeprivkey=" + privkey + "<br>";
    ui->detailText->setHtml(desc);
}

ImadaNodeConfigDialog::~ImadaNodeConfigDialog()
{
    delete ui;
}
