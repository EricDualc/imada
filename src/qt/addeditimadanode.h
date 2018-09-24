#ifndef ADDEDITIMADANODE_H
#define ADDEDITIMADANODE_H

#include <QDialog>

namespace Ui {
class AddEditImadaNode;
}


class AddEditImadaNode : public QDialog
{
    Q_OBJECT

public:
    explicit AddEditImadaNode(QWidget *parent = 0);
    ~AddEditImadaNode();

protected:

private slots:
    void on_okButton_clicked();
    void on_cancelButton_clicked();

signals:

private:
    Ui::AddEditImadaNode *ui;
};

#endif // ADDEDITIMADANODE_H
