#ifndef IMADANODECONFIGDIALOG_H
#define IMADANODECONFIGDIALOG_H

#include <QDialog>

namespace Ui {
    class ImadaNodeConfigDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Dialog showing transaction details. */
class ImadaNodeConfigDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ImadaNodeConfigDialog(QWidget *parent = 0, QString nodeAddress = "123.456.789.123:28666", QString privkey="MASTERNODEPRIVKEY");
    ~ImadaNodeConfigDialog();

private:
    Ui::ImadaNodeConfigDialog *ui;
};

#endif // IMADANODECONFIGDIALOG_H
